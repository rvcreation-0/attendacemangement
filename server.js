import crypto from 'node:crypto';
import { promisify } from 'node:util';
import express from 'express';
import { MongoClient } from 'mongodb';
import { readFile } from 'node:fs/promises';

const scrypt = promisify(crypto.scrypt);

const app = express();
const port = Number(process.env.PORT || 4173);
const dbName = process.env.MONGODB_DB || 'webcraft_attendance';

let mongoUri = process.env.MONGODB_URI;

if (!mongoUri) {
  try {
    mongoUri = (await readFile('.env', 'utf8'))
      .match(/^MONGODB_URI=(.+)$/m)?.[1]?.trim();
  } catch (_) {
    // Environment variables remain supported
  }
}

const attempts = new Map();

const emptyState = () => ({
  currentUser: null,
  admins: [],
  teachers: [],
  students: [],
  courses: [],
  batches: [],
  attendanceRecords: []
});

app.disable('x-powered-by');

app.use(express.json({ limit: '1mb' }));
app.use(express.static('public'));

app.use((_req, res, next) => {
  res.set({
    'Cache-Control': 'no-store, private',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'same-origin',
    'Permissions-Policy': 'camera=(), microphone=(), geolocation=()'
  });

  next();
});

let client;
let database;

async function getDatabase() {
  if (!mongoUri) {
    throw new Error('MONGODB_URI is not configured.');
  }

  if (!database) {
    client = new MongoClient(mongoUri, {
      serverSelectionTimeoutMS: 8000,
      connectTimeoutMS: 8000
    });

    try {
      await client.connect();

      database = client.db(dbName);

      await Promise.all([
        database
          .collection('accounts')
          .createIndex({ email: 1 }, { unique: true }),

        database
          .collection('accounts')
          .createIndex({ profileId: 1 }, { unique: true }),

        database
          .collection('sessions')
          .createIndex(
            { expiresAt: 1 },
            { expireAfterSeconds: 0 }
          ),

        database
          .collection('sessions')
          .createIndex(
            { tokenHash: 1 },
            { unique: true }
          ),

        database
          .collection('application_state')
          .createIndex(
            { key: 1 },
            { unique: true }
          )
      ]);
    } catch (error) {
      await client.close().catch(() => {});
      client = undefined;
      throw error;
    }
  }

  return database;
}

const email = value =>
  String(value || '')
    .trim()
    .toLowerCase();

const validEmail = value =>
  /^\S+@\S+\.\S+$/.test(value || '');

const validPassword = value =>
  typeof value === 'string' &&
  value.length >= 8 &&
  value.length <= 200;

const shortId = prefix =>
  `${prefix}-${crypto.randomInt(1000, 10000)}`;

const attendanceDateAllowed = value => {
  const date = String(value || '');
  if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) return false;

  const today = new Date();
  today.setHours(0, 0, 0, 0);
  const selected = new Date(`${date}T00:00:00`);
  const earliest = new Date(today);
  earliest.setDate(earliest.getDate() - 7);

  return selected >= earliest && selected <= today;
};

const publicAccount = account => ({
  id: account.profileId,
  entityId: account.profileId,
  name: account.name,
  email: account.email,
  role: account.role
});

const tokenHash = token =>
  crypto
    .createHash('sha256')
    .update(token)
    .digest('hex');

function cookies(req) {
  return Object.fromEntries(
    (req.headers.cookie || '')
      .split(';')
      .filter(Boolean)
      .map(x => {
        const i = x.indexOf('=');

        return [
          x.slice(0, i).trim(),
          decodeURIComponent(x.slice(i + 1))
        ];
      })
  );
}

async function hash(password) {
  const salt = crypto
    .randomBytes(16)
    .toString('hex');

  const key = await scrypt(
    password,
    salt,
    64
  );

  return `scrypt$${salt}$${Buffer
    .from(key)
    .toString('hex')}`;
}

async function verify(password, encoded) {
  const [
    scheme,
    salt,
    encodedKey
  ] = String(encoded).split('$');

  if (
    scheme !== 'scrypt' ||
    !salt ||
    !encodedKey
  ) {
    return false;
  }

  const actual = Buffer.from(
    await scrypt(password, salt, 64)
  );

  const expected = Buffer.from(
    encodedKey,
    'hex'
  );

  return (
    actual.length === expected.length &&
    crypto.timingSafeEqual(
      actual,
      expected
    )
  );
}

async function session(account, res) {
  const token = crypto
    .randomBytes(32)
    .toString('base64url');

  const db = await getDatabase();

  await db.collection('sessions').insertOne({
    tokenHash: tokenHash(token),
    accountId: account._id,
    expiresAt: new Date(
      Date.now() + 604800000
    ),
    createdAt: new Date()
  });

  res.cookie('wc_session', token, {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
    maxAge: 604800000,
    path: '/'
  });
}

async function requireAuth(req, res, next) {
  try {
    const token = cookies(req).wc_session;

    if (!token) {
      return res
        .status(401)
        .json({
          error: 'Sign in is required.'
        });
    }

    const db = await getDatabase();

    const saved =
      await db
        .collection('sessions')
        .findOne({
          tokenHash: tokenHash(token),
          expiresAt: {
            $gt: new Date()
          }
        });

    const account =
      saved &&
      await db
        .collection('accounts')
        .findOne({
          _id: saved.accountId,
          disabled: {
            $ne: true
          }
        });

    if (!account) {
      return res
        .status(401)
        .json({
          error:
            'Your session has expired. Please sign in again.'
        });
    }

    req.account = account;
    req.sessionToken = token;

    next();

  } catch (err) {
    next(err);
  }
}

const requireAdmin = (req, res, next) =>
  req.account?.role === 'admin'
    ? next()
    : res
        .status(403)
        .json({
          error:
            'Administrator access is required.'
        });

const requireBatchManager = (req, res, next) =>
  ['admin', 'teacher'].includes(req.account?.role)
    ? next()
    : res
        .status(403)
        .json({
          error:
            'Administrator or teacher access is required.'
        });

function rateLimit(req, res, next) {
  const key =
    `${req.ip}:${email(req.body?.email)}`;

  const now = Date.now();

  const item =
    attempts.get(key) || {
      count: 0,
      resetAt: now + 900000
    };

  if (item.resetAt <= now) {
    item.count = 0;
    item.resetAt = now + 900000;
  }

  if (item.count >= 5) {
    res.set(
      'Retry-After',
      String(
        Math.ceil(
          (item.resetAt - now) / 1000
        )
      )
    );

    return res
      .status(429)
      .json({
        error:
          'Too many sign-in attempts. Try again later.'
      });
  }

  req.limitKey = key;
  req.limitItem = item;

  next();
}

const failLogin = req =>
  attempts.set(
    req.limitKey,
    {
      ...req.limitItem,
      count: req.limitItem.count + 1
    }
  );

/*
========================================================
MULTI-BATCH STATE
========================================================
*/

async function scopedState(account) {
  const db = await getDatabase();

  const stored =
    await db
      .collection('application_state')
      .findOne({
        key: 'primary'
      });

  const state = structuredClone(
    stored?.value || emptyState()
  );

  state.currentUser =
    publicAccount(account);

  state.admins = [];

  // ADMIN
  if (account.role === 'admin') {
    const accounts = await db
      .collection('accounts')
      .find({ role: { $in: ['student', 'teacher'] }, disabled: { $ne: true } })
      .project({ profileId: 1, name: 1, email: 1, role: 1 })
      .toArray();

    for (const role of ['student', 'teacher']) {
      state[`${role}s`] = accounts
        .filter(savedAccount => savedAccount.role === role)
        .map(savedAccount => ({
          id: savedAccount.profileId,
          name: savedAccount.name,
          email: savedAccount.email,
          role
        }));
    }

    const studentIds = new Set(state.students.map(student => student.id));
    const teacherIds = new Set(state.teachers.map(teacher => teacher.id));
    state.batches = state.batches.map(batch => ({
      ...batch,
      student_ids: (batch.student_ids || []).filter(id => studentIds.has(id)),
      teacher_ids: (batch.teacher_ids || []).filter(id => teacherIds.has(id)),
      teacher_id: teacherIds.has(batch.teacher_id) ? batch.teacher_id : ''
    }));
    const batchIds = new Set(state.batches.map(batch => batch.id));
    state.attendanceRecords = state.attendanceRecords.filter(record =>
      batchIds.has(record.batch_id) && studentIds.has(record.student_id)
    );

    await db.collection('application_state').updateOne(
      { key: 'primary' },
      { $set: { value: cleanState(state), updatedAt: new Date() } },
      { upsert: true }
    );
    return state;
  }

  // TEACHER
  if (account.role === 'teacher') {

    const assignedBatches =
      state.batches.filter(batch =>
        batch.teacher_id === account.profileId ||
        (
          Array.isArray(batch.teacher_ids) &&
          batch.teacher_ids.includes(
            account.profileId
          )
        )
      );

    const batchIds =
      new Set(
        assignedBatches.map(
          batch => batch.id
        )
      );

    const studentIds =
      new Set(
        assignedBatches.flatMap(
          batch => batch.student_ids || []
        )
      );

    state.teachers =
      state.teachers.filter(
        teacher =>
          teacher.id === account.profileId
      );

    state.batches =
      assignedBatches;

    state.attendanceRecords =
      state.attendanceRecords.filter(
        attendance =>
          batchIds.has(
            attendance.batch_id
          )
      );

    return state;
  }

  // STUDENT
  const enrolledBatches =
    state.batches.filter(
      batch =>
        (batch.student_ids || [])
          .includes(account.profileId)
    );

  const batchIds =
    new Set(
      enrolledBatches.map(
        batch => batch.id
      )
    );

  const teacherIds =
    new Set(
      enrolledBatches
        .flatMap(batch =>
          Array.isArray(batch.teacher_ids)
            ? batch.teacher_ids
            : [batch.teacher_id]
        )
        .filter(Boolean)
    );

  state.students =
    state.students.filter(
      student =>
        student.id === account.profileId
    );

  state.teachers =
    state.teachers.filter(
      teacher =>
        teacherIds.has(teacher.id)
    );

  state.batches =
    enrolledBatches;

  state.attendanceRecords =
    state.attendanceRecords.filter(
      attendance =>
        batchIds.has(
          attendance.batch_id
        )
    );

  return state;
}

/*
========================================================
SANITIZE
========================================================
*/

function sanitize(value) {

  if (typeof value === 'string') {
    return value.replace(
      /[<>]/g,
      ''
    );
  }

  if (Array.isArray(value)) {
    return value.map(sanitize);
  }

  if (
    value &&
    typeof value === 'object'
  ) {
    return Object.fromEntries(
      Object.entries(value).map(
        ([key, item]) =>
          [key, sanitize(item)]
      )
    );
  }

  return value;
}

function cleanState(state) {

  state =
    state &&
    typeof state === 'object'
      ? state
      : emptyState();

  return sanitize({
    currentUser: null,

    admins: [],

    teachers:
      Array.isArray(state.teachers)
        ? state.teachers.map(
            ({ password, ...x }) => x
          )
        : [],

    students:
      Array.isArray(state.students)
        ? state.students.map(
            ({ password, ...x }) => x
          )
        : [],

    courses:
      Array.isArray(state.courses)
        ? state.courses
        : [],

    batches:
      Array.isArray(state.batches)
        ? state.batches
        : [],

    attendanceRecords:
      Array.isArray(
        state.attendanceRecords
      )
        ? state.attendanceRecords
        : []
  });
}

/*
========================================================
BATCH NORMALIZATION
========================================================
*/

function normalizeBatch(batch = {}) {

  const studentIds =
    [
      ...new Set(
        (
          Array.isArray(
            batch.student_ids
          )
            ? batch.student_ids
            : []
        )
          .map(x =>
            String(x || '').trim()
          )
          .filter(Boolean)
      )
    ];

  const teacherIds =
    [
      ...new Set(
        [
          ...(Array.isArray(
            batch.teacher_ids
          )
            ? batch.teacher_ids
            : []),

          batch.teacher_id
        ]
          .map(x =>
            String(x || '').trim()
          )
          .filter(Boolean)
      )
    ];

  return {
    id:
      String(
        batch.id ||
        crypto.randomUUID()
      ),

    name:
      String(
        batch.name || ''
      ).trim(),

    course_id:
      batch.course_id
        ? String(
            batch.course_id
          ).trim()
        : '',

    teacher_id:
      teacherIds[0] || '',

    teacher_ids:
      teacherIds,

    student_ids:
      studentIds,

    createdAt:
      batch.createdAt ||
      new Date().toISOString(),

    updatedAt:
      new Date().toISOString()
  };
}

/*
========================================================
NORMALIZE ADMIN STATE
========================================================
*/

function normalizeStateForAdmin(input) {

  const state =
    cleanState(input);

  state.teachers =
    state.teachers
      .map(teacher => ({
        ...teacher,
        id: String(
          teacher.id ||
          teacher.profileId ||
          ''
        ).trim()
      }))
      .filter(
        teacher => teacher.id
      );

  state.students =
    state.students
      .map(student => ({
        ...student,
        id: String(
          student.id ||
          student.profileId ||
          ''
        ).trim()
      }))
      .filter(
        student => student.id
      );

  state.batches =
    state.batches
      .map(normalizeBatch)
      .filter(
        batch => batch.name
      );

  const studentSet =
    new Set(
      state.students.map(
        student => student.id
      )
    );

  const teacherSet =
    new Set(
      state.teachers.map(
        teacher => teacher.id
      )
    );

  state.batches =
    state.batches.map(batch => ({
      ...batch,

      student_ids:
        batch.student_ids.filter(
          id => studentSet.has(id)
        ),

      teacher_ids:
        batch.teacher_ids.filter(
          id => teacherSet.has(id)
        ),

      teacher_id:
        batch.teacher_ids.find(
          id => teacherSet.has(id)
        ) || ''
    }));

  const batchIds =
    new Set(
      state.batches.map(
        batch => batch.id
      )
    );

  const studentIds =
    new Set(
      state.students.map(
        student => student.id
      )
    );

  state.attendanceRecords =
    state.attendanceRecords.filter(
      record =>
        batchIds.has(
          String(record.batch_id)
        ) &&

        studentIds.has(
          String(record.student_id)
        ) &&

        ['present', 'absent']
          .includes(record.status) &&

        /^\d{4}-\d{2}-\d{2}$/
          .test(
            String(record.date)
          )
    );

  return state;
}

/*
========================================================
CREATE BATCH
========================================================
*/

app.post(
  '/api/batches',
  requireAuth,
  requireBatchManager,
  async (req, res, next) => {

    try {

      const db =
        await getDatabase();

      const stored =
        (
          await db
            .collection(
              'application_state'
            )
            .findOne({
              key: 'primary'
            })
        )?.value ||
        emptyState();

      const batch =
        normalizeBatch(
          req.body || {}
        );

      if (!batch.name) {
        return res
          .status(400)
          .json({
            error:
              'Batch name is required.'
          });
      }

      const validStudents =
        new Set(
          (stored.students || [])
            .map(
              student => student.id
            )
        );

      const validTeachers =
        new Set(
          (stored.teachers || [])
            .map(
              teacher => teacher.id
            )
        );

      batch.student_ids =
        batch.student_ids.filter(
          id =>
            validStudents.has(id)
        );

      batch.teacher_ids =
        batch.teacher_ids.filter(
          id =>
            validTeachers.has(id)
        );

      if (req.account.role === 'teacher') {
        batch.teacher_ids = [req.account.profileId];
      }

      batch.teacher_id =
        batch.teacher_ids[0] || '';

      stored.batches = [
        ...(stored.batches || []),
        batch
      ];

      await db
        .collection(
          'application_state'
        )
        .updateOne(
          {
            key: 'primary'
          },
          {
            $set: {
              value:
                normalizeStateForAdmin(
                  stored
                ),
              updatedAt:
                new Date()
            }
          },
          {
            upsert: true
          }
        );

      res
        .status(201)
        .json({
          batch
        });

    } catch (err) {
      next(err);
    }
  }
);

/*
========================================================
UPDATE BATCH
========================================================
*/

app.put(
  '/api/batches/:id',
  requireAuth,
  requireBatchManager,
  async (req, res, next) => {

    try {

      const db =
        await getDatabase();

      const stored =
        (
          await db
            .collection(
              'application_state'
            )
            .findOne({
              key: 'primary'
            })
        )?.value ||
        emptyState();

      const index =
        (stored.batches || [])
          .findIndex(
            batch =>
              String(batch.id) ===
              String(req.params.id)
          );

      if (index < 0) {
        return res
          .status(404)
          .json({
            error:
              'Batch not found.'
          });
      }

      if (
        req.account.role === 'teacher' &&
        !(
          stored.batches[index].teacher_id === req.account.profileId ||
          stored.batches[index].teacher_ids?.includes(req.account.profileId)
        )
      ) {
        return res.status(403).json({
          error: 'You can only edit batches assigned to you.'
        });
      }

      const updated =
        normalizeBatch({
          ...stored.batches[index],
          ...(req.body || {}),
          id: req.params.id
        });

      if (!updated.name) {
        return res
          .status(400)
          .json({
            error:
              'Batch name is required.'
          });
      }

      const validStudents =
        new Set(
          (stored.students || [])
            .map(
              student => student.id
            )
        );

      const validTeachers =
        new Set(
          (stored.teachers || [])
            .map(
              teacher => teacher.id
            )
        );

      updated.student_ids =
        updated.student_ids.filter(
          id =>
            validStudents.has(id)
        );

      updated.teacher_ids =
        updated.teacher_ids.filter(
          id =>
            validTeachers.has(id)
        );

      if (req.account.role === 'teacher') {
        updated.teacher_ids = [req.account.profileId];
      }

      updated.teacher_id =
        updated.teacher_ids[0] || '';

      stored.batches[index] =
        updated;

      await db
        .collection(
          'application_state'
        )
        .updateOne(
          {
            key: 'primary'
          },
          {
            $set: {
              value:
                normalizeStateForAdmin(
                  stored
                ),
              updatedAt:
                new Date()
            }
          },
          {
            upsert: true
          }
        );

      res.json({
        batch: updated
      });

    } catch (err) {
      next(err);
    }
  }
);

/*
========================================================
DELETE BATCH
========================================================
*/

app.delete(
  '/api/batches/:id',
  requireAuth,
  requireAdmin,
  async (req, res, next) => {

    try {

      const db =
        await getDatabase();

      const stored =
        (
          await db
            .collection(
              'application_state'
            )
            .findOne({
              key: 'primary'
            })
        )?.value ||
        emptyState();

      const id =
        String(req.params.id);

      if (
        !(stored.batches || [])
          .some(
            batch =>
              String(batch.id) === id
          )
      ) {
        return res
          .status(404)
          .json({
            error:
              'Batch not found.'
          });
      }

      stored.batches =
        (stored.batches || [])
          .filter(
            batch =>
              String(batch.id) !== id
          );

      stored.attendanceRecords =
        (
          stored.attendanceRecords ||
          []
        ).filter(
          attendance =>
            String(
              attendance.batch_id
            ) !== id
        );

      await db
        .collection(
          'application_state'
        )
        .updateOne(
          {
            key: 'primary'
          },
          {
            $set: {
              value:
                normalizeStateForAdmin(
                  stored
                ),
              updatedAt:
                new Date()
            }
          },
          {
            upsert: true
          }
        );

      res
        .status(204)
        .end();

    } catch (err) {
      next(err);
    }
  }
);

/*
========================================================
HEALTH
========================================================
*/

app.get(
  '/api/health',
  async (_req, res) => {

    try {

      await (
        await getDatabase()
      ).command({
        ping: 1
      });

      res.json({
        ok: true,
        database: dbName
      });

    } catch (err) {

      res
        .status(503)
        .json({
          ok: false,
          error: err.message
        });
    }
  }
);

/*
========================================================
REGISTRATION STATUS
========================================================
*/

app.get(
  '/api/auth/registration-status',
  async (_req, res, next) => {

    try {

      const db =
        await getDatabase();

      const adminCount =
        await db
          .collection('accounts')
          .countDocuments({
            role: 'admin'
          });

      res.json({
        needsAdminSetup:
          !adminCount
      });

    } catch (err) {
      next(err);
    }
  }
);

/*
========================================================
FIRST ADMIN
========================================================
*/

app.post(
  '/api/auth/register-first-admin',
  async (req, res, next) => {

    try {

      const {
        name,
        password
      } = req.body || {};

      const address =
        email(req.body?.email);

      if (
        !name?.trim() ||
        !validEmail(address) ||
        !validPassword(password)
      ) {
        return res
          .status(400)
          .json({
            error:
              'Enter a name, valid email, and password of at least 8 characters.'
          });
      }

      const db =
        await getDatabase();

      if (
        await db
          .collection('accounts')
          .countDocuments({
            role: 'admin'
          })
      ) {
        return res
          .status(403)
          .json({
            error:
              'An administrator already exists.'
          });
      }

      const account = {
        name: name.trim(),
        email: address,
        role: 'admin',

        profileId:
          shortId('ADM'),

        passwordHash:
          await hash(password),

        createdAt:
          new Date()
      };

      await db
        .collection('accounts')
        .insertOne(account);

      await session(
        account,
        res
      );

      res
        .status(201)
        .json({
          account:
            publicAccount(
              account
            )
        });

    } catch (err) {
      next(err);
    }
  }
);

/*
========================================================
LOGIN
========================================================
*/

app.post(
  '/api/auth/login',
  rateLimit,
  async (req, res, next) => {

    try {

      const password =
        req.body?.password;

      const address =
        email(req.body?.email);

      const db =
        await getDatabase();

      const account =
        validEmail(address) &&
        await db
          .collection('accounts')
          .findOne({
            email: address,
            disabled: {
              $ne: true
            }
          });

      if (
        !account ||
        !(await verify(
          password,
          account.passwordHash
        ))
      ) {

        failLogin(req);

        return res
          .status(401)
          .json({
            error:
              'Invalid email or password.'
          });
      }

      attempts.delete(
        req.limitKey
      );

      await session(
        account,
        res
      );

      res.json({
        account:
          publicAccount(
            account
          )
      });

    } catch (err) {
      next(err);
    }
  }
);

/*
========================================================
LOGOUT
========================================================
*/

app.post(
  '/api/auth/logout',
  requireAuth,
  async (req, res, next) => {

    try {

      await (
        await getDatabase()
      )
        .collection('sessions')
        .deleteOne({
          tokenHash:
            tokenHash(
              req.sessionToken
            )
        });

      res
        .clearCookie(
          'wc_session',
          {
            path: '/'
          }
        )
        .status(204)
        .end();

    } catch (err) {
      next(err);
    }
  }
);

/*
========================================================
CURRENT USER
========================================================
*/

app.get(
  '/api/auth/me',
  requireAuth,
  (req, res) => {

    res.json({
      account:
        publicAccount(
          req.account
        )
    });
  }
);

/*
========================================================
CREATE USER
========================================================
*/

app.post(
  '/api/users',
  requireAuth,
  requireAdmin,
  async (req, res, next) => {

    try {

      const {
        name,
        password,
        role,
        profileId
      } = req.body || {};

      const address =
        email(req.body?.email);

      if (
        !['teacher', 'student']
          .includes(role) ||

        String(profileId || '').trim().length > 12 ||

        !name?.trim() ||

        !validEmail(address) ||

        !validPassword(password)
      ) {

        return res
          .status(400)
          .json({
            error:
              'Name, email, role, and an 8-character password are required.'
          });
      }

      const db =
        await getDatabase();

      let generatedProfileId = String(profileId || '').trim();
      if (!generatedProfileId) {
        do {
          generatedProfileId = shortId(
            role === 'teacher' ? 'TCH' : 'STD'
          );
        } while (
          await db
            .collection('accounts')
            .findOne({ profileId: generatedProfileId })
        );
      }

      const account = {
        name: name.trim(),
        email: address,
        role,
        profileId: generatedProfileId,

        passwordHash:
          await hash(password),

        createdAt:
          new Date()
      };

      await db
        .collection('accounts')
        .insertOne(account);

      const stored =
        (
          await db
            .collection(
              'application_state'
            )
            .findOne({
              key: 'primary'
            })
        )?.value ||
        emptyState();

      const profile = {
        id: generatedProfileId,
        name: name.trim(),
        email: address,
        role
      };

      if (role === 'teacher') {

        stored.teachers = [
          ...(stored.teachers || [])
            .filter(
              x =>
                x.id !== generatedProfileId
            ),

          profile
        ];

      } else {

        stored.students = [
          ...(stored.students || [])
            .filter(
              x =>
                x.id !== generatedProfileId
            ),

          profile
        ];
      }

      await db
        .collection(
          'application_state'
        )
        .updateOne(
          {
            key: 'primary'
          },
          {
            $set: {
              value:
                cleanState(
                  stored
                ),

              updatedAt:
                new Date()
            }
          },
          {
            upsert: true
          }
        );

      res
        .status(201)
        .json({
          account:
            publicAccount(
              account
            )
        });

    } catch (err) {
      next(err);
    }
  }
);

/*
========================================================
UPDATE USER
========================================================
*/

app.put(
  '/api/users/:profileId',
  requireAuth,
  requireAdmin,
  async (req, res, next) => {

    try {

      const update = {
        updatedAt:
          new Date()
      };

      const address =
        req.body?.email;

      if (
        req.body?.name?.trim()
      ) {
        update.name =
          req.body.name.trim();
      }

      if (address) {

        if (
          !validEmail(address)
        ) {
          return res
            .status(400)
            .json({
              error:
                'A valid email is required.'
            });
        }

        update.email =
          email(address);
      }

      if (req.body?.password) {

        if (
          !validPassword(
            req.body.password
          )
        ) {
          return res
            .status(400)
            .json({
              error:
                'Password must be at least 8 characters.'
            });
        }

        update.passwordHash =
          await hash(
            req.body.password
          );
      }

      const db = await getDatabase();
      const accountBefore = await db.collection('accounts').findOne({
        profileId: req.params.profileId,
        disabled: { $ne: true }
      });

      if (!accountBefore) {

        return res
          .status(404)
          .json({
            error:
              'Account not found.'
          });
      }

      await db.collection('accounts').updateOne(
        { _id: accountBefore._id },
        { $set: update }
      );
      const account = await db.collection('accounts').findOne({ _id: accountBefore._id });
      const stored = (await db.collection('application_state').findOne({ key: 'primary' }))?.value || emptyState();
      const profileLists = account.role === 'student' ? ['students'] : ['teachers'];
      for (const listName of profileLists) {
        stored[listName] = (stored[listName] || []).map(profile =>
          profile.id === account.profileId
            ? { ...profile, name: account.name, email: account.email }
            : profile
        );
      }
      await db.collection('application_state').updateOne(
        { key: 'primary' },
        { $set: { value: cleanState(stored), updatedAt: new Date() } },
        { upsert: true }
      );

      res.json({
        account:
          publicAccount(
            account
          )
      });

    } catch (err) {
      next(err);
    }
  }
);

/*
========================================================
DELETE USER
========================================================
*/

app.delete(
  '/api/users/:profileId',
  requireAuth,
  requireAdmin,
  async (req, res, next) => {

    try {

      const db = await getDatabase();
      const result = await db
        .collection('accounts')
        .deleteOne({
          profileId: req.params.profileId,
          disabled: { $ne: true }
        });

      if (!result.deletedCount) {
        return res.status(404).json({ error: 'Student not found.' });
      }

      const stored = (await db.collection('application_state').findOne({ key: 'primary' }))?.value || emptyState();
      stored.students = (stored.students || []).filter(profile => profile.id !== req.params.profileId);
      stored.teachers = (stored.teachers || []).filter(profile => profile.id !== req.params.profileId);
      stored.batches = (stored.batches || []).map(batch => ({
        ...batch,
        student_ids: (batch.student_ids || []).filter(id => id !== req.params.profileId),
        teacher_ids: (batch.teacher_ids || []).filter(id => id !== req.params.profileId),
        teacher_id: batch.teacher_id === req.params.profileId ? '' : batch.teacher_id
      }));
      stored.attendanceRecords = (stored.attendanceRecords || []).filter(record => record.student_id !== req.params.profileId);
      await db.collection('application_state').updateOne(
        { key: 'primary' },
        { $set: { value: normalizeStateForAdmin(stored), updatedAt: new Date() } },
        { upsert: true }
      );

      res
        .status(204)
        .end();

    } catch (err) {
      next(err);
    }
  }
);

/*
========================================================
GET STATE
========================================================
*/

app.get(
  '/api/state',
  requireAuth,
  async (req, res, next) => {

    try {

      res.json({
        state:
          await scopedState(
            req.account
          )
      });

    } catch (err) {
      next(err);
    }
  }
);

/*
========================================================
UPDATE STATE
========================================================
*/

app.put(
  '/api/state',
  requireAuth,
  async (req, res, next) => {

    try {

      if (!req.body?.state) {

        return res
          .status(400)
          .json({
            error:
              'A state object is required.'
          });
      }

      const db =
        await getDatabase();

      /*
      ================================================
      ADMIN
      ================================================
      */

      if (
        req.account.role ===
        'admin'
      ) {

        const normalized =
          normalizeStateForAdmin(
            req.body.state
          );

        await db
          .collection(
            'application_state'
          )
          .updateOne(
            {
              key: 'primary'
            },

            {
              $set: {
                value: normalized,
                updatedAt:
                  new Date()
              }
            },

            {
              upsert: true
            }
          );

        return res.json({
          ok: true
        });
      }

      /*
      ================================================
      TEACHER
      ================================================
      */

      if (
        req.account.role ===
        'teacher'
      ) {

        const stored =
          (
            await db
              .collection(
                'application_state'
              )
              .findOne({
                key: 'primary'
              })
          )?.value ||
          emptyState();

        const assignedBatches =
          (stored.batches || [])
            .filter(batch =>
              batch.teacher_id ===
                req.account.profileId ||

              (
                Array.isArray(
                  batch.teacher_ids
                ) &&

                batch.teacher_ids.includes(
                  req.account.profileId
                )
              )
            );

        const assignedBatchIds =
          new Set(
            assignedBatches.map(
              batch => batch.id
            )
          );

        const teacherUpdates =
          (
            req.body.state
              .attendanceRecords || []
          )
            .filter(attendance =>

              assignedBatchIds.has(
                String(
                  attendance.batch_id
                )
              ) &&

              String(
                attendance.student_id ||
                ''
              ).trim() &&

              attendanceDateAllowed(
                attendance.date
              ) &&

              ['present', 'absent']
                .includes(
                  attendance.status
                )
            )
            .map(attendance => ({
              batch_id:
                String(
                  attendance.batch_id
                ),

              student_id:
                String(
                  attendance.student_id
                ),

              date:
                String(
                  attendance.date
                ),

              status:
                attendance.status,

              lecture_name:
                String(
                  attendance.lecture_name ||
                  ''
                ).trim().slice(0, 120)
            }));

        const lockedKeys = new Set(
          teacherUpdates.map(
            attendance =>
              `${attendance.batch_id}|${attendance.date}`
          )
        );

        const alreadySaved = (
          stored.attendanceRecords || []
        ).some(attendance =>
          lockedKeys.has(
            `${attendance.batch_id}|${attendance.date}`
          )
        );

        if (alreadySaved) {
          return res.status(409).json({
            error:
              'Attendance for this batch and date is already locked.'
          });
        }

        /*
        Replace only the submitted
        batch/date combinations.
        */

        const updateKeys =
          new Set(
            teacherUpdates.map(
              attendance =>
                `${attendance.batch_id}|${attendance.date}`
            )
          );

        stored.attendanceRecords = [
          ...(
            stored.attendanceRecords ||
            []
          ).filter(
            attendance =>
              !updateKeys.has(
                `${attendance.batch_id}|${attendance.date}`
              )
          ),

          ...teacherUpdates
        ];

        await db
          .collection(
            'application_state'
          )
          .updateOne(
            {
              key: 'primary'
            },

            {
              $set: {
                value:
                  cleanState(
                    stored
                  ),

                updatedAt:
                  new Date()
              }
            },

            {
              upsert: true
            }
          );

        return res.json({
          ok: true
        });
      }

      /*
      ================================================
      STUDENT
      ================================================
      */

      return res
        .status(403)
        .json({
          error:
            'Students have read-only access.'
        });

    } catch (err) {
      next(err);
    }
  }
);

/*
========================================================
ERROR HANDLER
========================================================
*/

app.use(
  (err, _req, res, _next) => {

    if (err?.code === 11000) {

      return res
        .status(409)
        .json({
          error:
            'That email address is already in use.'
        });
    }

    console.error(err);

    res
      .status(500)
      .json({
        error:
          'The server could not complete that request.'
      });
  }
);

/*
========================================================
START SERVER
========================================================
*/

let server;

if (!process.env.NETLIFY) {
  server =
    app.listen(
      port,
      () =>
        console.log(
          `Webcraft Attendance is running on http://localhost:${port}`
        )
    );
}

/*
========================================================
GRACEFUL SHUTDOWN
========================================================
*/

async function close() {

  server?.close();

  await client?.close();
}

process.on(
  'SIGINT',
  close
);

process.on(
  'SIGTERM',
  close
);

export { app };