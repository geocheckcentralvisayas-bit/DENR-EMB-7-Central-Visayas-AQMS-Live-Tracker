/**
 * AQMS APPLICATION AUTHENTICATION AND DATA-ACCESS SERVICE
 *
 * Public requester:
 *   - No login required.
 *   - Submits an access request.
 *
 * Administrator:
 *   - Uses AQMS application username/password.
 *   - Reviews pending requests.
 *   - Approves/rejects requests.
 *   - Can download approved exports.
 *
 * Required Script Properties:
 *   WEB_APP_URL
 *   MONITORING_SPREADSHEET_ID
 *   MONITORING_SHEETS
 *   APPROVAL_EXPIRATION_HOURS (optional, default 24)
 *
 * Run once:
 *   setupApprovalSystem()
 *   setupAdminAccount()
 */

const AQMS_HEADERS = [
  "REQUEST ID",
  "REQUESTER NAME",
  "REQUESTER EMAIL",
  "REQUEST DATE/TIME",
  "REQUEST TYPE",
  "DATA TYPE",
  "STATION/LGU",
  "PARAMETER",
  "DATE FROM",
  "DATE TO",
  "CATEGORY",
  "DATA SOURCE",
  "SEARCH QUERY",
  "RECORD COUNT",
  "REASON",
  "STATUS",
  "APPROVED BY",
  "APPROVED BY EMAIL",
  "APPROVED DATE/TIME",
  "REJECTION REASON",
  "EXPIRATION DATE/TIME",
  "REQUEST TOKEN",
  "SCOPE HASH",
  "REJECTED BY",
  "REJECTED BY EMAIL",
  "REJECTION DATE/TIME",
  "EXPORT FILE ID",
  "EXPORT GENERATED DATE/TIME",
  "EXPORT RECORD COUNT",
  "USER ID",
  "CONTACT NUMBER",
  "LGU",
  "EXPORT FILE NAME"
];

const ADMIN_HEADERS = [
  "ADMIN USER ID",
  "USERNAME",
  "PASSWORD HASH",
  "ROLE",
  "STATUS",
  "CREATED DATE/TIME",
  "LAST LOGIN"
];

const ADMIN_SESSION_HEADERS = [
  "SESSION HASH",
  "ADMIN USER ID",
  "USERNAME",
  "ROLE",
  "CREATED DATE/TIME",
  "EXPIRATION DATE/TIME",
  "STATUS"
];

const AUDIT_HEADERS = [
  "TIMESTAMP",
  "USER ID",
  "USERNAME",
  "ROLE",
  "REQUEST ID",
  "ACTION",
  "DATA SCOPE",
  "RESULT",
  "DETAILS"
];

const REGISTRY_SHEET = "AQMS_ACCESS_REQUESTS";
const ADMIN_USERS_SHEET = "AQMS_ADMIN_USERS";
const ADMIN_SESSIONS_SHEET = "AQMS_ADMIN_SESSIONS";
const AUDIT_SHEET = "AQMS_ACCESS_AUDIT";
const REGISTRY_SPREADSHEET_ID =
  "1xpH9RMIAOMlxjAKAFGSTy1ZQDLKbxB0cM2sm_EX-B3w";

const SESSION_HOURS = 8;
const PASSWORD_ITERATIONS = 100000;


/* =========================================================
   PUBLIC WEB ENTRY
   ========================================================= */

function doGet(e) {
  const action = String(
    (e && e.parameter && e.parameter.action) || "health"
  ).trim();

  if (action === "admin") {
    return HtmlService
      .createHtmlOutputFromFile("admin")
      .setTitle("AQMS Administrator Portal");
  }

  if (action === "request") {
    let scope = {};

    try {
      scope = JSON.parse(
        String((e && e.parameter && e.parameter.scope) || "{}")
      );
    } catch (error) {
      return HtmlService
        .createHtmlOutput(
          "<h1>Invalid data access request</h1><p>The captured dashboard scope could not be read. Please return to the AQMS dashboard and try again.</p>"
        )
        .setTitle("AQMS Data Access Request");
    }

    const template = HtmlService.createTemplateFromFile("request");
    template.scopeJson = encodeURIComponent(JSON.stringify(scope));

    return template
      .evaluate()
      .setTitle("AQMS Data Access Request");
  }

  if (action === "health") {
    return json_({
      ok: true,
      service: "AQMS application access service"
    });
  }

  if (action === "version") {
    return json_(adminAuthVersion_());
  }

  if (action === "diagnose") {
    return json_(diagnoseApprovalSystem());
  }

  if (action === "download") {
    return downloadApprovedRequest_(e ? e.parameter : {});
  }

  return json_({
    ok: false,
    error: "Use POST for authenticated operations"
  });
}


/* =========================================================
   PUBLIC POST ENTRY
   ========================================================= */

function doPost(e) {
  let body = {};

  try {
    body = JSON.parse(
      (e && e.postData && e.postData.contents) || "{}"
    );
  } catch (error) {
    return json_({
      ok: false,
      error: "Invalid JSON request"
    });
  }

  try {
    return json_(
      approvalAction(
        body.action,
        body
      )
    );

  } catch (error) {

    const message = String(
      error && error.message || error
    );

    let safeMessage = message;

    if (
      message === "SESSION_EXPIRED" ||
      message === "INVALID_SESSION" ||
      message === "AUTHENTICATION_REQUIRED"
    ) {
      safeMessage =
        "Your AQMS administrator session has expired. Please sign in again.";
    }

    if (message === "ADMIN_ACCESS_DENIED") {
      safeMessage =
        "DENIED: administrator access required.";
    }

    return json_({
      ok: false,
      error: safeMessage
    });
  }
}


/* =========================================================
   IMPORTANT GOOGLE.SCRIPT.RUN BRIDGE
   =========================================================
   
   admin.html calls:

       google.script.run.approvalAction(action, payload)

   Functions ending in "_" are private and cannot be called
   directly by google.script.run.

   This public bridge fixes that connection.
   ========================================================= */

function approvalAction(action, payload) {

  payload = payload || {};

  const selectedAction = String(action || "").trim();

  try {
    switch (selectedAction) {

      case "adminLogin":
        return adminLogin_(payload);

      case "logout":
        return logoutAdmin_(payload);

      case "submit":
        return submitAccessRequest(
          payload.request || payload
        );

      case "status":
        return statusRequest_(payload);

      case "verify":
        return verifyAccessRequest_(payload);

      case "export":
        return exportApprovedRequest_(payload);

      case "exportApprovedRequest":
        return exportApprovedRequest_(payload);

      case "adminSummary":
        return adminSummary_(
          payload.sessionToken
        );

      case "adminRequests":
        return adminRequests_(
          payload.sessionToken,
          payload.status
        );

      case "adminRequest":
        return adminRequest_(
          payload.sessionToken,
          payload.requestId
        );

      case "adminDownload":
        return adminDownloadExport_(payload);

      case "emailPrepared":
        return emailPrepared_(payload);

      case "approve":
        return approveRequest_(payload);

      case "reject":
        return rejectRequest_(payload);

      case "audit":
        return auditLog_(
          payload.sessionToken
        );

      case "version":
        return adminAuthVersion_();

      default:
        return {
          ok: false,
          error: "Unsupported administrator action: " +
            selectedAction
        };
    }
  } catch (error) {
    return {
      ok: false,
      error: String(
        error && error.message || error
      )
    };
  }
}


/* =========================================================
   ADMIN LOGIN
   ========================================================= */

function adminLogin_(body) {

  const username = normalizeUsername_(
    body.username
  );

  const password = String(
    body.password || ""
  );

  const adminRecord =
    findAdminByUsername_(username);

  if (
    !adminRecord ||
    String(adminRecord.row[3]) !== "ADMIN" ||
    String(adminRecord.row[4]) !== "ACTIVE" ||
    !verifyAdminPassword_(
      password,
      String(adminRecord.row[2])
    )
  ) {

    auditEvent_(
      null,
      {
        username: username,
        role: "ADMIN"
      },
      "ADMIN_LOGIN_FAILED",
      "DENIED",
      "Invalid administrator credentials"
    );

    return {
      ok: false,
      error: "Invalid administrator username or password."
    };
  }

  const admin =
    adminProfile_(adminRecord);

  const session =
    createSession_(admin);

  adminRecord.sheet
    .getRange(
      adminRecord.rowNumber,
      7
    )
    .setValue(
      new Date().toISOString()
    );

  auditEvent_(
    null,
    admin,
    "ADMIN_LOGIN_SUCCESS",
    "SUCCESS",
    "Administrator session created"
  );

  return {
    ok: true,
    sessionToken: session.token,
    expires: session.expires,
    role: "ADMIN",
    username: admin.username
  };
}


/* =========================================================
   CREATE / RESET DEVELOPMENT ADMIN
   ========================================================= */

function setupAdminAccount() {

  const normalized = "admin";
  const password = "admin";

  const sheet =
    adminUsersSheet_();

  const rows =
    sheet.getDataRange().getValues();

  const matches = [];

  for (
    let i = 1;
    i < rows.length;
    i++
  ) {

    if (
      String(rows[i][1])
        .toLowerCase() === normalized
    ) {

      matches.push({
        sheet: sheet,
        rowNumber: i + 1,
        row: rows[i]
      });
    }
  }

  if (matches.length) {

    const primary = matches[0];

    const salt =
      Utilities.getUuid() +
      Utilities.getUuid();

    const passwordHash =
      passwordHash_(
        password,
        salt
      );

    sheet
      .getRange(
        primary.rowNumber,
        2,
        1,
        5
      )
      .setValues([
        [
          normalized,
          salt + "$" + passwordHash,
          "ADMIN",
          "ACTIVE",
          primary.row[5] ||
            new Date().toISOString()
        ]
      ]);

    matches
      .slice(1)
      .forEach(match => {

        sheet
          .getRange(
            match.rowNumber,
            5
          )
          .setValue("INACTIVE");
      });

    for (
      let i = 1;
      i < rows.length;
      i++
    ) {

      if (
        String(rows[i][3]) === "ADMIN" &&
        String(rows[i][1])
          .toLowerCase() !== normalized
      ) {

        sheet
          .getRange(
            i + 1,
            5
          )
          .setValue("INACTIVE");
      }
    }

    return {
      ok: true,
      username: normalized,
      created: false,
      message:
        "Administrator account reset successfully."
    };
  }

  const salt =
    Utilities.getUuid() +
    Utilities.getUuid();

  sheet.appendRow([
    "ADMIN",
    normalized,
    salt + "$" +
      passwordHash_(
        password,
        salt
      ),
    "ADMIN",
    "ACTIVE",
    new Date().toISOString(),
    ""
  ]);

  return {
    ok: true,
    username: normalized,
    created: true,
    message:
      "Administrator account created successfully."
  };
}


/* =========================================================
   LOGOUT
   ========================================================= */

function logoutAdmin_(body) {

  const admin =
    authenticateSession_(
      body.sessionToken,
      "ADMIN"
    );

  const sheet =
    adminSessionsSheet_();

  const values =
    sheet.getDataRange().getValues();

  const tokenHash =
    hash_(
      String(
        body.sessionToken || ""
      )
    );

  for (
    let i = 1;
    i < values.length;
    i++
  ) {

    if (
      secureEqual_(
        String(values[i][0]),
        tokenHash
      )
    ) {

      sheet
        .getRange(i + 1, 7)
        .setValue("REVOKED");
    }
  }

  auditEvent_(
    null,
    admin,
    "ADMIN_LOGOUT",
    "SUCCESS",
    ""
  );

  return {
    ok: true
  };
}


/* =========================================================
   SUBMIT PUBLIC ACCESS REQUEST
   ========================================================= */

function submitAccessRequest(request) {

  const normalized =
    validateRequest_(request);

  const token =
    Utilities.getUuid() +
    Utilities.getUuid();

  const now =
    new Date();

  const requestId =
    "AQMS-ACCESS-" +
    Utilities.formatDate(
      now,
      Session.getScriptTimeZone(),
      "yyyyMMdd"
    ) +
    "-" +
    Utilities
      .getUuid()
      .replace(/-/g, "")
      .slice(0, 8)
      .toUpperCase();

  const scopeHash =
    hash_(
      scopeString_(normalized)
    );

  /*
   * IMPORTANT:
   * AQMS_HEADERS contains exactly 33 columns.
   *
   * This row also contains exactly 33 values.
   */
  const row = [

    /* 1  */ requestId,
    /* 2  */ normalized.requesterName,
    /* 3  */ normalized.requesterEmail,
    /* 4  */ now.toISOString(),
    /* 5  */ normalized.requestType,
    /* 6  */ normalized.dataType,
    /* 7  */ normalized.stationOrLGU,
    /* 8  */ normalized.parameter,
    /* 9  */ normalized.dateFrom,
    /* 10 */ normalized.dateTo,
    /* 11 */ normalized.category,
    /* 12 */ normalized.dataSource,
    /* 13 */ normalized.searchQuery,
    /* 14 */ normalized.recordCount,
    /* 15 */ normalized.reason,
    /* 16 */ "PENDING",
    /* 17 */ "",
    /* 18 */ "",
    /* 19 */ "",
    /* 20 */ "",
    /* 21 */ "",
    /* 22 */ token,
    /* 23 */ scopeHash,
    /* 24 */ "",
    /* 25 */ "",
    /* 26 */ "",
    /* 27 */ "",
    /* 28 */ "",
    /* 29 */ "",
    /* 30 */ "",
    /* 31 */ normalized.contactNumber,
    /* 32 */ normalized.lgu,
    /* 33 */ ""
  ];

  const sheet =
    registrySheet_();

  sheet.appendRow(row);

  auditEvent_(
    requestId,
    {
      userId: "",
      username:
        normalized.requesterEmail,
      role: "PUBLIC"
    },
    "REQUEST_CREATED",
    "PENDING",
    scopeString_(normalized)
  );

  return {
    ok: true,
    requestId: requestId,
    status: "PENDING",
    requestToken: token,
    scopeHash: scopeHash
  };
}


/* =========================================================
   PUBLIC REQUEST STATUS
   ========================================================= */

function statusRequest_(body) {

  const found =
    findRequest_(
      body.requestId
    );

  if (
    !found ||
    !secureEqual_(
      String(found.row[21] || ""),
      String(body.requestToken || "")
    )
  ) {

    throw new Error(
      "Request not found"
    );
  }

  const status =
    expireIfNeeded_(found);

  auditEvent_(
    found.row[0],
    {
      userId: "",
      username: found.row[2],
      role: "PUBLIC"
    },
    "REQUEST_VIEWED",
    "SUCCESS",
    "Request status viewed"
  );

  return {
    ok: true,
    request: safeRequest_(
      rowToRequest_(
        found.row
      ),
      status
    )
  };
}


/* =========================================================
   ADMIN SUMMARY
   ========================================================= */

function adminSummary_(token) {

  const admin =
    authenticateSession_(
      token,
      "ADMIN"
    );

  cleanupExpiredExports_();

  const counts = {
    pending: 0,
    approved: 0,
    rejected: 0,
    expired: 0
  };

  allRequests_()
    .forEach(item => {

      const status =
        currentStatus_(item)
          .toLowerCase();

      counts[status] =
        (counts[status] || 0) + 1;
    });

  auditEvent_(
    null,
    admin,
    "ADMIN_VIEW",
    "SUCCESS",
    "Dashboard counters viewed"
  );

  return {
    ok: true,
    counts: counts
  };
}


/* =========================================================
   ADMIN REQUEST LIST
   ========================================================= */

function adminRequests_(
  token,
  status
) {

  const admin =
    authenticateSession_(
      token,
      "ADMIN"
    );

  const requestedStatus =
    String(status || "")
      .trim()
      .toUpperCase();

  const requests =
    allRequests_()
      .filter(item => {

        if (!requestedStatus) {
          return true;
        }

        return (
          currentStatus_(item) ===
          requestedStatus
        );
      })
      .map(safeRequest_);

  auditEvent_(
    null,
    admin,
    "ADMIN_VIEW",
    "SUCCESS",
    "Request list viewed"
  );

  return {
    ok: true,
    requests: requests
  };
}


/* =========================================================
   ADMIN REQUEST DETAILS
   ========================================================= */

function adminRequest_(
  token,
  requestId
) {

  const admin =
    authenticateSession_(
      token,
      "ADMIN"
    );

  const found =
    findRequest_(
      requestId
    );

  if (!found) {
    throw new Error(
      "Request not found"
    );
  }

  const status =
    expireIfNeeded_(found);

  auditEvent_(
    requestId,
    admin,
    "ADMIN_VIEW",
    "SUCCESS",
    "Request details viewed"
  );

  return {
    ok: true,
    request: safeRequest_(
      rowToRequest_(
        found.row
      ),
      status
    )
  };
}


/* =========================================================
   APPROVE REQUEST
   ========================================================= */

function approveRequest_(body) {

  const lock =
    LockService.getScriptLock();

  if (
    !lock.tryLock(10000)
  ) {
    throw new Error(
      "Approval operation is busy; try again"
    );
  }

  try {
    return approveRequestLocked_(body);
  } finally {
    lock.releaseLock();
  }
}


function approveRequestLocked_(body) {

  const admin =
    authenticateSession_(
      body.sessionToken,
      "ADMIN"
    );

  const found =
    findRequest_(
      body.requestId
    );

  if (!found) {
    throw new Error(
      "Request not found"
    );
  }

  const stored =
    rowToRequest_(
      found.row
    );

  const status =
    expireIfNeeded_(found);

  if (status !== "PENDING") {
    throw new Error(
      "Only pending requests can be approved"
    );
  }

  if (
    !body.requestToken ||
    !secureEqual_(
      String(body.requestToken),
      String(stored.requestToken)
    )
  ) {

    throw new Error(
      "Request identity verification failed"
    );
  }

  if (
    !body.scopeHash ||
    !secureEqual_(
      String(body.scopeHash),
      String(stored.scopeHash)
    )
  ) {

    throw new Error(
      "Request scope verification failed"
    );
  }

  const now =
    new Date();

  const expiration =
    new Date(
      now.getTime() +
      config_().expirationHours *
      60 *
      60 *
      1000
    );

  found.sheet
    .getRange(
      found.rowNumber,
      16,
      1,
      6
    )
    .setValues([
      [
        "APPROVED",
        admin.username,
        admin.email || "",
        now.toISOString(),
        "",
        expiration.toISOString()
      ]
    ]);

  found.row[15] = "APPROVED";
  found.row[16] = admin.username;
  found.row[17] = admin.email || "";
  found.row[18] = now.toISOString();
  found.row[19] = "";
  found.row[20] = expiration.toISOString();

  auditEvent_(
    stored.requestId,
    admin,
    "APPROVED",
    "SUCCESS",
    scopeString_(stored)
  );

  let exportReady = false;
  let exportFileName = "";

  try {

    const artifact =
      generateExportArtifact_(
        rowToRequest_(
          found.row
        )
      );

    const file =
      DriveApp.createFile(
        artifact.fileName,
        artifact.csv,
        MimeType.CSV
      );

    file.setTrashed(false);

    found.sheet
      .getRange(
        found.rowNumber,
        27,
        1,
        3
      )
      .setValues([
        [
          file.getId(),
          now.toISOString(),
          artifact.recordCount
        ]
      ]);

    found.sheet
      .getRange(
        found.rowNumber,
        33
      )
      .setValue(
        artifact.fileName
      );

    exportReady = true;
    exportFileName =
      artifact.fileName;

    auditEvent_(
      stored.requestId,
      admin,
      "EXPORT_GENERATED",
      "SUCCESS",
      "Approved export prepared"
    );

  } catch (error) {

    auditEvent_(
      stored.requestId,
      admin,
      "EXPORT_GENERATED",
      "FAILED",
      String(
        error &&
        error.message ||
        error
      )
    );
  }

  return {
    ok: true,
    requestId:
      stored.requestId,
    status: "APPROVED",
    expirationDateTime:
      expiration.toISOString(),
    exportReady:
      exportReady,
    exportFileName:
      exportFileName
  };
}


/* =========================================================
   REJECT REQUEST
   ========================================================= */

function rejectRequest_(body) {

  const lock =
    LockService.getScriptLock();

  if (
    !lock.tryLock(10000)
  ) {
    throw new Error(
      "Review operation is busy; try again"
    );
  }

  try {
    return rejectRequestLocked_(body);
  } finally {
    lock.releaseLock();
  }
}


function rejectRequestLocked_(body) {

  const admin =
    authenticateSession_(
      body.sessionToken,
      "ADMIN"
    );

  const reason =
    requiredString_(
      body.rejectionReason,
      "Rejection reason"
    );

  const found =
    findRequest_(
      body.requestId
    );

  if (!found) {
    throw new Error(
      "Request not found"
    );
  }

  const stored =
    rowToRequest_(
      found.row
    );

  if (
    expireIfNeeded_(found) !==
    "PENDING"
  ) {
    throw new Error(
      "Only pending requests can be rejected"
    );
  }

  const now =
    new Date().toISOString();

  found.sheet
    .getRange(
      found.rowNumber,
      16,
      1,
      6
    )
    .setValues([
      [
        "REJECTED",
        admin.username,
        admin.email || "",
        now,
        reason,
        ""
      ]
    ]);

  found.sheet
    .getRange(
      found.rowNumber,
      24,
      1,
      3
    )
    .setValues([
      [
        admin.username,
        admin.email || "",
        now
      ]
    ]);

  auditEvent_(
    stored.requestId,
    admin,
    "REQUEST_REJECTED",
    "SUCCESS",
    reason
  );

  return {
    ok: true,
    requestId:
      stored.requestId,
    status: "REJECTED"
  };
}


/* =========================================================
   ADMIN DOWNLOAD
   ========================================================= */

function adminDownloadExport_(body) {

  const admin =
    authenticateSession_(
      body.sessionToken,
      "ADMIN"
    );

  const found =
    findRequest_(
      body.requestId
    );

  if (!found) {
    throw new Error(
      "Request not found"
    );
  }

  const stored =
    rowToRequest_(
      found.row
    );

  if (
    expireIfNeeded_(found) !==
    "APPROVED"
  ) {

    throw new Error(
      "Approved export is no longer available"
    );
  }

  if (!stored.exportFileId) {
    throw new Error(
      "Approved export is not available"
    );
  }

  const file =
    DriveApp.getFileById(
      stored.exportFileId
    );

  auditEvent_(
    stored.requestId,
    admin,
    "EXPORT_DOWNLOADED",
    "SUCCESS",
    "Administrator downloaded approved export"
  );

  return {
    ok: true,
    csv:
      file.getBlob()
        .getDataAsString(),
    fileName:
      stored.exportFileName ||
      (
        "aqms-approved-" +
        stored.requestId +
        ".csv"
      )
  };
}


/* =========================================================
   EMAIL PREPARED
   ========================================================= */

function emailPrepared_(body) {

  const admin =
    authenticateSession_(
      body.sessionToken,
      "ADMIN"
    );

  const found =
    findRequest_(
      body.requestId
    );

  if (!found) {
    throw new Error(
      "Request not found"
    );
  }

  const stored =
    rowToRequest_(
      found.row
    );

  if (
    expireIfNeeded_(found) !==
    "APPROVED"
  ) {

    throw new Error(
      "Approved request is no longer available"
    );
  }

  auditEvent_(
    stored.requestId,
    admin,
    "EMAIL_PREPARED",
    "SUCCESS",
    "Administrator prepared a manual email"
  );

  return {
    ok: true,
    requesterEmail:
      stored.requesterEmail,
    requesterName:
      stored.requesterName,
    fileName:
      stored.exportFileName || ""
  };
}


/* =========================================================
   VERIFY PUBLIC APPROVAL
   ========================================================= */

function verifyAccessRequest_(body) {

  const found =
    findRequest_(
      body.requestId
    );

  if (
    !found ||
    !secureEqual_(
      String(found.row[21] || ""),
      String(body.requestToken || "")
    )
  ) {

    return {
      ok: true,
      authorized: false
    };
  }

  const status =
    expireIfNeeded_(found);

  const stored =
    rowToRequest_(
      found.row
    );

  const requestedScope =
    body.scope || {};

  const authorized =
    status === "APPROVED" &&
    stored.requestType ===
      String(body.operation || "") &&
    stored.scopeHash ===
      hash_(
        scopeString_(
          requestedScope
        )
      );

  return {
    ok: true,
    authorized:
      authorized,
    status:
      status,
    requestId:
      stored.requestId
  };
}


/* =========================================================
   PUBLIC APPROVED EXPORT
   ========================================================= */

function exportApprovedRequest_(body) {

  const found =
    findRequest_(
      body.requestId
    );

  if (
    !found ||
    !secureEqual_(
      String(found.row[21] || ""),
      String(body.requestToken || "")
    )
  ) {

    throw new Error(
      "Request not found"
    );
  }

  const status =
    expireIfNeeded_(found);

  const stored =
    rowToRequest_(
      found.row
    );

  if (
    status !== "APPROVED" ||
    stored.requestType !==
      String(body.operation || "") ||
    stored.scopeHash !==
      hash_(
        scopeString_(
          body.scope || {}
        )
      )
  ) {

    auditEvent_(
      stored.requestId,
      {
        userId: "",
        username:
          stored.requesterEmail,
        role: "PUBLIC"
      },
      "DOWNLOAD_EXPIRED",
      "DENIED",
      "Approval or scope verification failed"
    );

    throw new Error(
      "Approved export is not valid for this session and scope"
    );
  }

  if (!stored.exportFileId) {
    throw new Error(
      "Approved export is not available"
    );
  }

  const file =
    DriveApp.getFileById(
      stored.exportFileId
    );

  auditEvent_(
    stored.requestId,
    {
      userId: "",
      username:
        stored.requesterEmail,
      role: "PUBLIC"
    },
    "DOWNLOAD",
    "SUCCESS",
    "Approved export downloaded"
  );

  return {
    ok: true,
    csv:
      file.getBlob()
        .getDataAsString(),
    fileName:
      stored.exportFileName ||
      (
        "aqms-approved-" +
        stored.requestId +
        ".csv"
      )
  };
}


/* =========================================================
   AUDIT LOG
   ========================================================= */

function auditLog_(token) {

  const admin =
    authenticateSession_(
      token,
      "ADMIN"
    );

  const sheet =
    auditSheet_();

  const values =
    sheet.getDataRange()
      .getValues();

  const entries =
    values
      .slice(1)
      .reverse()
      .slice(0, 500)
      .map(row => ({
        timestamp: row[0],
        userId: row[1],
        username: row[2],
        role: row[3],
        requestId: row[4],
        action: row[5],
        dataScope: row[6],
        result: row[7],
        details: row[8]
      }));

  auditEvent_(
    null,
    admin,
    "ADMIN_VIEW",
    "SUCCESS",
    "Audit log viewed"
  );

  return {
    ok: true,
    entries: entries
  };
}


/* =========================================================
   SESSION AUTHENTICATION
   ========================================================= */

function authenticateSession_(
  token,
  requiredRole
) {

  const raw =
    String(token || "");

  if (!raw) {
    throw new Error(
      "AUTHENTICATION_REQUIRED"
    );
  }

  const sheet =
    adminSessionsSheet_();

  const values =
    sheet.getDataRange()
      .getValues();

  const tokenHash =
    hash_(raw);

  for (
    let i = 1;
    i < values.length;
    i++
  ) {

    if (
      secureEqual_(
        String(values[i][0]),
        tokenHash
      )
    ) {

      if (
        String(values[i][6]) !==
        "ACTIVE"
      ) {
        throw new Error(
          "SESSION_EXPIRED"
        );
      }

      const expiry =
        new Date(
          values[i][5]
        ).getTime();

      if (
        !isFinite(expiry) ||
        expiry <= Date.now()
      ) {

        sheet
          .getRange(
            i + 1,
            7
          )
          .setValue("EXPIRED");

        throw new Error(
          "SESSION_EXPIRED"
        );
      }

      const admin =
        findAdminById_(
          String(values[i][1])
        );

      if (
        !admin ||
        String(admin.row[4]) !==
        "ACTIVE"
      ) {
        throw new Error(
          "ACCOUNT_INACTIVE"
        );
      }

      const profile =
        adminProfile_(admin);

      const role =
        profile.role;

      if (
        requiredRole &&
        role !== requiredRole
      ) {

        auditEvent_(
          null,
          profile,
          "ADMIN_ACCESS_DENIED",
          "DENIED",
          "Insufficient role"
        );

        throw new Error(
          "ADMIN_ACCESS_DENIED"
        );
      }

      return profile;
    }
  }

  throw new Error(
    "INVALID_SESSION"
  );
}


/* =========================================================
   CREATE SESSION
   ========================================================= */

function createSession_(user) {

  const profile =
    user.row
      ? adminProfile_(user)
      : user;

  const token =
    Utilities.getUuid() +
    Utilities.getUuid();

  const now =
    new Date();

  const expires =
    new Date(
      now.getTime() +
      SESSION_HOURS *
      60 *
      60 *
      1000
    );

  adminSessionsSheet_()
    .appendRow([
      hash_(token),
      profile.adminUserId,
      profile.username,
      profile.role,
      now.toISOString(),
      expires.toISOString(),
      "ACTIVE"
    ]);

  return {
    token: token,
    expires:
      expires.toISOString()
  };
}


/* =========================================================
   ADMIN LOOKUP
   ========================================================= */

function findAdminByUsername_(
  username
) {

  const sheet =
    adminUsersSheet_();

  const values =
    sheet.getDataRange()
      .getValues();

  for (
    let i = 1;
    i < values.length;
    i++
  ) {

    if (
      String(values[i][1])
        .trim()
        .toLowerCase() ===
      String(username)
        .trim()
        .toLowerCase()
    ) {

      return {
        sheet: sheet,
        rowNumber: i + 1,
        row: values[i]
      };
    }
  }

  return null;
}


function findAdminById_(
  adminUserId
) {

  const sheet =
    adminUsersSheet_();

  const values =
    sheet.getDataRange()
      .getValues();

  for (
    let i = 1;
    i < values.length;
    i++
  ) {

    if (
      String(values[i][0]) ===
      String(adminUserId)
    ) {

      return {
        sheet: sheet,
        rowNumber: i + 1,
        row: values[i]
      };
    }
  }

  return null;
}


/* =========================================================
   ADMIN PROFILE
   ========================================================= */

function adminProfile_(admin) {

  return {
    adminUserId:
      admin.row[0],
    username:
      admin.row[1],
    role:
      admin.row[3],
    status:
      admin.row[4],
    email: ""
  };
}


/* =========================================================
   SHEETS
   ========================================================= */

function adminUsersSheet_() {
  return ensureSheet_(
    ADMIN_USERS_SHEET,
    ADMIN_HEADERS
  );
}


function adminSessionsSheet_() {
  return ensureSheet_(
    ADMIN_SESSIONS_SHEET,
    ADMIN_SESSION_HEADERS
  );
}


function registrySheet_() {
  return ensureSheet_(
    REGISTRY_SHEET,
    AQMS_HEADERS
  );
}


function auditSheet_() {
  return ensureSheet_(
    AUDIT_SHEET,
    AUDIT_HEADERS
  );
}


/* =========================================================
   ENSURE REGISTRY SPREADSHEET
   ========================================================= */

function ensureSheet_(
  name,
  headers
) {

  const props =
    PropertiesService
      .getScriptProperties();

  const id =
    props.getProperty(
      "REGISTRY_SPREADSHEET_ID"
    ) ||
    REGISTRY_SPREADSHEET_ID;

  const spreadsheet =
    SpreadsheetApp.openById(id);

  let sheet =
    spreadsheet.getSheetByName(
      name
    );

  if (!sheet) {

    sheet =
      spreadsheet.insertSheet(
        name
      );
  }

  if (
    sheet.getLastRow() === 0
  ) {

    sheet
      .getRange(
        1,
        1,
        1,
        headers.length
      )
      .setValues([
        headers
      ]);

  } else if (
    sheet.getLastColumn() <
    headers.length
  ) {

    const currentColumns =
      sheet.getLastColumn();

    sheet
      .getRange(
        1,
        currentColumns + 1,
        1,
        headers.length -
          currentColumns
      )
      .setValues([
        headers.slice(
          currentColumns
        )
      ]);
  }

  return sheet;
}


/* =========================================================
   REQUEST RETRIEVAL
   ========================================================= */

function allRequests_() {

  const sheet =
    registrySheet_();

  const values =
    sheet.getDataRange()
      .getValues();

  return values
    .slice(1)
    .filter(row => row[0])
    .map(row =>
      rowToRequest_(row)
    );
}


function findRequest_(
  requestId
) {

  const sheet =
    registrySheet_();

  const values =
    sheet.getDataRange()
      .getValues();

  for (
    let i = 1;
    i < values.length;
    i++
  ) {

    if (
      String(values[i][0]) ===
      String(requestId || "")
    ) {

      return {
        sheet: sheet,
        rowNumber: i + 1,
        row: values[i]
      };
    }
  }

  return null;
}


/* =========================================================
   REQUEST OWNERSHIP
   ========================================================= */

function requestBelongsTo_(
  found,
  user
) {

  return (
    String(found.row[29] || "") ===
    String(user.userId || "")
  );
}


/* =========================================================
   ROW -> REQUEST OBJECT
   ========================================================= */

function rowToRequest_(
  row,
  statusOverride
) {

  row = row || [];

  return {

    requestId:
      row[0] || "",

    requesterName:
      row[1] || "",

    requesterEmail:
      row[2] || "",

    requestDateTime:
      row[3] || "",

    requestType:
      row[4] || "",

    dataType:
      row[5] || "",

    stationOrLGU:
      row[6] || "",

    parameter:
      row[7] || "",

    dateFrom:
      row[8] || "",

    dateTo:
      row[9] || "",

    category:
      row[10] || "",

    dataSource:
      row[11] || "",

    searchQuery:
      row[12] || "",

    recordCount:
      row[13] || 0,

    reason:
      row[14] || "",

    status:
      statusOverride ||
      row[15] ||
      "PENDING",

    approvedBy:
      row[16] || "",

    approvedByEmail:
      row[17] || "",

    approvedDateTime:
      row[18] || "",

    rejectionReason:
      row[19] || "",

    expirationDateTime:
      row[20] || "",

    requestToken:
      row[21] || "",

    scopeHash:
      row[22] || "",

    rejectedBy:
      row[23] || "",

    rejectedByEmail:
      row[24] || "",

    rejectionDateTime:
      row[25] || "",

    exportFileId:
      row[26] || "",

    exportGeneratedDateTime:
      row[27] || "",

    exportRecordCount:
      row[28] || 0,

    userId:
      row[29] || "",

    contactNumber:
      row[30] || "",

    lgu:
      row[31] || "",

    exportFileName:
      row[32] || ""
  };
}


/* =========================================================
   SAFE REQUEST OBJECT FOR ADMIN UI
   ========================================================= */

function serializeDate_(
  value
) {

  if (!value) {
    return "";
  }

  if (
    Object.prototype.toString.call(value) ===
      "[object Date]" &&
    !isNaN(value.getTime())
  ) {

    return Utilities.formatDate(
      value,
      Session.getScriptTimeZone(),
      "yyyy-MM-dd HH:mm:ss"
    );
  }

  return String(value);
}


function safeRequest_(
  request
) {

  return {

    requestId:
      request.requestId,

    requesterName:
      request.requesterName,

    requestDateTime:
      serializeDate_(
        request.requestDateTime
      ),

    requesterEmail:
      request.requesterEmail,

    requestType:
      request.requestType,

    dataType:
      request.dataType,

    stationOrLGU:
      request.stationOrLGU,

    parameter:
      request.parameter,

    dateFrom:
      serializeDate_(
        request.dateFrom
      ),

    dateTo:
      serializeDate_(
        request.dateTo
      ),

    category:
      request.category,

    dataSource:
      request.dataSource,

    searchQuery:
      request.searchQuery,

    recordCount:
      request.recordCount,

    reason:
      request.reason,

    status:
      currentStatus_(request),

    approvedBy:
      request.approvedBy,

    approvedDateTime:
      serializeDate_(
        request.approvedDateTime
      ),

    rejectionReason:
      request.rejectionReason,

    expirationDateTime:
      serializeDate_(
        request.expirationDateTime
      ),

    scopeHash:
      request.scopeHash,

    userId:
      request.userId,

    contactNumber:
      request.contactNumber,

    lgu:
      request.lgu,

    requestToken:
      request.requestToken,

    exportGeneratedDateTime:
      serializeDate_(
        request.exportGeneratedDateTime
      ),

    exportRecordCount:
      request.exportRecordCount,

    exportReady:
      Boolean(
        request.exportGeneratedDateTime &&
        request.exportFileId
      ),

    exportFileName:
      request.exportFileName || ""
  };
}


/* =========================================================
   STATUS
   ========================================================= */

function currentStatus_(
  request
) {

  if (
    request.status === "APPROVED" &&
    request.expirationDateTime
  ) {

    const expiration =
      new Date(
        request.expirationDateTime
      ).getTime();

    if (
      isFinite(expiration) &&
      expiration <= Date.now()
    ) {

      return "EXPIRED";
    }
  }

  return request.status;
}


/* =========================================================
   CLEANUP EXPIRED EXPORTS
   ========================================================= */

function cleanupExpiredExports_() {

  const sheet =
    registrySheet_();

  const values =
    sheet.getDataRange()
      .getValues();

  values
    .slice(1)
    .forEach(
      (row, index) => {

        if (
          !row[26] ||
          !row[20]
        ) {
          return;
        }

        const expiration =
          new Date(
            row[20]
          ).getTime();

        if (
          !isFinite(expiration) ||
          expiration > Date.now()
        ) {
          return;
        }

        try {

          DriveApp
            .getFileById(
              String(row[26])
            )
            .setTrashed(true);

        } catch (error) {
          // File may already be gone.
        }

        sheet
          .getRange(
            index + 2,
            27
          )
          .clearContent();

        sheet
          .getRange(
            index + 2,
            28,
            1,
            2
          )
          .clearContent();
      }
    );
}


/* =========================================================
   EXPIRE REQUEST
   ========================================================= */

function expireIfNeeded_(
  found
) {

  const request =
    rowToRequest_(
      found.row
    );

  const status =
    currentStatus_(request);

  if (
    status === "EXPIRED" &&
    found.row[15] !== "EXPIRED"
  ) {

    found.sheet
      .getRange(
        found.rowNumber,
        16
      )
      .setValue("EXPIRED");
  }

  return status;
}


/* =========================================================
   AUDIT
   ========================================================= */

function auditEvent_(
  requestId,
  actor,
  action,
  result,
  details
) {

  const profile =
    actor || {};

  auditSheet_()
    .appendRow([
      new Date().toISOString(),
      profile.userId ||
        profile.adminUserId ||
        "",
      profile.username || "",
      profile.role || "",
      requestId || "",
      action || "",
      details || "",
      result || "",
      details || ""
    ]);
}


function auditScope_(
  request
) {
  return scopeString_(request);
}


/* =========================================================
   SCOPE STRING
   ========================================================= */

function scopeString_(
  request
) {

  request =
    request || {};

  return [
    request.requestType,
    request.dataType,
    request.stationOrLGU ||
      request.station,
    request.parameter,
    request.dateFrom,
    request.dateTo,
    request.category,
    request.dataSource,
    request.searchQuery
  ]
    .map(
      value =>
        String(value || "")
    )
    .join("|");
}


/* =========================================================
   VALIDATE REQUEST
   ========================================================= */

function validateRequest_(
  request
) {

  request =
    request || {};

  [
    "requesterName",
    "requesterEmail",
    "requestType",
    "dataType",
    "contactNumber",
    "reason"
  ].forEach(
    key =>
      requiredString_(
        request[key],
        key
      )
  );

  if (
    !/^[^\s@]+@[^\s@]+\.[^\s@]+$/
      .test(
        String(
          request.requesterEmail
        ).trim()
      )
  ) {

    throw new Error(
      "Invalid requester email"
    );
  }

  const validTypes = [
    "Export Filtered Data",
    "Export All Data",
    "Export All Available Data",
    "Print Data"
  ];

  const validData = [
    "All Data",
    "Continuous Monitoring",
    "Manual LGU Monitoring"
  ];

  const requestType =
    String(
      request.requestType
    ).trim();

  const dataType =
    String(
      request.dataType
    ).trim();

  if (
    validTypes.indexOf(
      requestType
    ) < 0
  ) {

    throw new Error(
      "Invalid request type"
    );
  }

  if (
    validData.indexOf(
      dataType
    ) < 0
  ) {

    throw new Error(
      "Invalid data type"
    );
  }

  return {

    requesterName:
      String(
        request.requesterName
      ).trim(),

    requesterEmail:
      String(
        request.requesterEmail
      )
        .trim()
        .toLowerCase(),

    requestType:
      requestType,

    dataType:
      dataType,

    stationOrLGU:
      String(
        request.stationOrLGU ||
        request.station ||
        "All stations / LGUs"
      ).trim(),

    parameter:
      String(
        request.parameter ||
        "All parameters"
      ).trim(),

    dateFrom:
      String(
        request.dateFrom ||
        "All dates"
      ).trim(),

    dateTo:
      String(
        request.dateTo ||
        "All dates"
      ).trim(),

    category:
      String(
        request.category ||
        "All categories"
      ).trim(),

    dataSource:
      String(
        request.dataSource ||
        "All sources"
      ).trim(),

    searchQuery:
      String(
        request.searchQuery ||
        ""
      ).trim(),

    recordCount:
      Number(
        request.recordCount ||
        request.requestedRecordsCount ||
        0
      ),

    reason:
      String(
        request.reason
      ).trim(),

    contactNumber:
      String(
        request.contactNumber
      ).trim(),

    /*
     * IMPORTANT:
     * Preserve LGU separately.
     */
    lgu:
      String(
        request.lgu || ""
      ).trim(),

    userId:
      String(
        request.userId || ""
      ).trim()
  };
}


/* =========================================================
   EXPORT GENERATOR
   ========================================================= */

function generateExportArtifact_(
  request
) {

  const props =
    PropertiesService
      .getScriptProperties();

  const id =
    String(
      props.getProperty(
        "MONITORING_SPREADSHEET_ID"
      ) || ""
    ).trim();

  const names =
    String(
      props.getProperty(
        "MONITORING_SHEETS"
      ) || ""
    )
      .split(",")
      .map(
        name => name.trim()
      )
      .filter(Boolean);

  if (
    !id ||
    !names.length
  ) {

    throw new Error(
      "Export adapter is not configured: set MONITORING_SPREADSHEET_ID and MONITORING_SHEETS"
    );
  }

  const spreadsheet =
    SpreadsheetApp.openById(
      id
    );

  const rows = [[
    "SOURCE",
    "STATION / LGU",
    "DATE",
    "TIME",
    "PARAMETER",
    "VALUE",
    "CATEGORY",
    "REMARKS"
  ]];

  names.forEach(
    name => {

      const sheet =
        spreadsheet.getSheetByName(
          name
        );

      if (!sheet) {

        throw new Error(
          "Configured monitoring sheet not found: " +
          name
        );
      }

      const values =
        sheet.getDataRange()
          .getDisplayValues();

      if (
        values.length < 2
      ) {
        return;
      }

      const headers =
        values[0]
          .map(
            normalizedHeader_
          );

      const source =
        name
          .toLowerCase()
          .trim() ===
        "manual datum"
          ? "manual"
          : "continuous";

      values
        .slice(1)
        .forEach(
          row => {

            const record =
              sourceRow_(
                headers,
                row,
                source
              );

            if (
              !record ||
              !matchesExportScope_(
                record,
                request,
                source
              )
            ) {
              return;
            }

            record.values
              .forEach(
                value => {

                  rows.push([
                    source === "manual"
                      ? "Manual LGU Monitoring"
                      : "Continuous Monitoring",

                    record.station,
                    record.date,
                    record.time,
                    value.name,
                    value.value,
                    value.category,
                    value.remarks
                  ]);
                }
              );
          }
        );
    }
  );

  if (
    rows.length === 1
  ) {

    throw new Error(
      "No monitoring records match the approved scope"
    );
  }

  return {

    csv:
      rows
        .map(
          row =>
            row
              .map(csvEscape_)
              .join(",")
        )
        .join("\r\n"),

    recordCount:
      rows.length - 1,

    fileName:
      "aqms-approved-" +
      request.requestId +
      ".csv"
  };
}


/* =========================================================
   HEADER NORMALIZATION
   ========================================================= */

function normalizedHeader_(
  value
) {

  return String(
    value || ""
  )
    .toLowerCase()
    .replace(
      /[^a-z0-9]/g,
      ""
    );
}


/* =========================================================
   COLUMN VALUE
   ========================================================= */

function columnValue_(
  headers,
  row,
  names
) {

  const normalizedNames =
    names.map(
      normalizedHeader_
    );

  let index = -1;

  for (
    let i = 0;
    i < normalizedNames.length;
    i++
  ) {

    const candidate =
      normalizedNames[i];

    const foundIndex =
      headers.indexOf(
        candidate
      );

    if (
      foundIndex >= 0
    ) {

      index =
        foundIndex;

      break;
    }
  }

  if (
    index < 0 ||
    index >= row.length
  ) {

    return "";
  }

  return String(
    row[index] || ""
  ).trim();
}


/* =========================================================
   SOURCE ROW
   ========================================================= */

function sourceRow_(
  headers,
  row,
  source
) {

  const station =
    columnValue_(
      headers,
      row,
      source === "manual"
        ? [
            "station",
            "lgu",
            "municipality",
            "city",
            "monitoringstation",
            "stationlgu"
          ]
        : [
            "station",
            "city",
            "monitoringstation"
          ]
    );

  const date =
    columnValue_(
      headers,
      row,
      [
        "samplingdate",
        "sampingdate",
        "date",
        "monitoringdate"
      ]
    );

  const time =
    columnValue_(
      headers,
      row,
      [
        "hour",
        "time",
        "samplingtime",
        "samplinghour"
      ]
    );

  if (
    !station ||
    !date
  ) {

    return null;
  }

  let values = [];

  if (
    source === "manual"
  ) {

    const pm10Value =
      columnValue_(
        headers,
        row,
        [
          "pm10",
          "pm10concentration",
          "pm10value"
        ]
      );

    const pm10Remarks =
      columnValue_(
        headers,
        row,
        [
          "remarkspm10",
          "pm10remarks",
          "remarks10",
          "remakrs10"
        ]
      );

    const tspValue =
      columnValue_(
        headers,
        row,
        [
          "tsp",
          "tspconcentration",
          "tspvalue",
          "totalsuspendedparticulate"
        ]
      );

    const tspRemarks =
      columnValue_(
        headers,
        row,
        [
          "remarkstsp",
          "tspremarks",
          "tspcategory"
        ]
      );

    /*
     * PM10 and TSP remain associated with
     * the SAME source row.
     */
    values = [

      {
        name: "PM10",
        value: pm10Value,
        category: pm10Remarks,
        remarks: pm10Remarks
      },

      {
        name: "TSP",
        value: tspValue,
        category: tspRemarks,
        remarks: tspRemarks
      }
    ];

  } else {

    const pm25Value =
      columnValue_(
        headers,
        row,
        [
          "pm25",
          "pm2.5",
          "pm25concentration"
        ]
      );

    const pm25Remarks =
      columnValue_(
        headers,
        row,
        [
          "remarks25",
          "remakrs25",
          "remarks25",
          "pm25remarks"
        ]
      );

    const pm10Value =
      columnValue_(
        headers,
        row,
        [
          "pm10",
          "pm10concentration"
        ]
      );

    const pm10Remarks =
      columnValue_(
        headers,
        row,
        [
          "remarkspm10",
          "remarks10",
          "remakrs10",
          "pm10remarks"
        ]
      );

    values = [

      {
        name: "PM2.5",
        value: pm25Value,
        category: "",
        remarks: pm25Remarks
      },

      {
        name: "PM10",
        value: pm10Value,
        category: "",
        remarks: pm10Remarks
      }
    ];
  }

  return {
    station:
      station,
    date:
      date,
    time:
      time,
    values:
      values.filter(
        value =>
          value.value !== "" ||
          value.remarks !== ""
      )
  };
}


/* =========================================================
   EXPORT SCOPE MATCH
   ========================================================= */

function matchesExportScope_(
  record,
  request,
  source
) {

  request =
    request || {};

  if (
    request.stationOrLGU &&
    request.stationOrLGU !==
      "All stations / LGUs" &&
    record.station !==
      request.stationOrLGU
  ) {

    return false;
  }

  /*
   * Date comparison.
   */
  if (
    request.dateFrom !==
      "All dates" &&
    request.dateFrom
  ) {

    const from =
      new Date(
        request.dateFrom +
        "T00:00:00"
      ).getTime();

    const recordDate =
      new Date(
        record.date
      ).getTime();

    if (
      isFinite(from) &&
      isFinite(recordDate) &&
      recordDate < from
    ) {

      return false;
    }
  }

  if (
    request.dateTo !==
      "All dates" &&
    request.dateTo
  ) {

    const to =
      new Date(
        request.dateTo +
        "T23:59:59"
      ).getTime();

    const recordDate =
      new Date(
        record.date
      ).getTime();

    if (
      isFinite(to) &&
      isFinite(recordDate) &&
      recordDate > to
    ) {

      return false;
    }
  }

  /*
   * Source.
   */
  if (
    request.dataSource &&
    request.dataSource !==
      "All sources"
  ) {

    const requestedSource =
      String(
        request.dataSource
      )
        .toLowerCase()
        .trim();

    if (
      requestedSource !==
        source.toLowerCase()
    ) {

      return false;
    }
  }

  /*
   * Data type.
   */
  if (
    request.dataType !==
      "All Data"
  ) {

    const manualRequested =
      request.dataType ===
      "Manual LGU Monitoring";

    if (
      manualRequested !==
      (source === "manual")
    ) {

      return false;
    }
  }

  const query =
    String(
      request.searchQuery || ""
    )
      .toLowerCase()
      .trim();

  return record.values.some(
    value => {

      if (
        request.parameter &&
        request.parameter !==
          "All parameters" &&
        value.name !==
          request.parameter
      ) {

        return false;
      }

      if (
        request.category &&
        request.category !==
          "All categories" &&
        value.category !==
          request.category
      ) {

        return false;
      }

      if (!query) {
        return true;
      }

      return [
        record.station,
        record.date,
        record.time,
        value.name,
        value.value,
        value.category,
        value.remarks
      ]
        .join(" ")
        .toLowerCase()
        .indexOf(query) >= 0;
    }
  );
}


/* =========================================================
   CSV ESCAPE
   ========================================================= */

function csvEscape_(
  value
) {

  return '"' +
    String(
      value == null
        ? ""
        : value
    ).replace(
      /"/g,
      '""'
    ) +
    '"';
}


/* =========================================================
   PUBLIC GET DOWNLOAD
   ========================================================= */

function downloadApprovedRequest_(
  params
) {

  return HtmlService
    .createHtmlOutput(
      "<h2>Download denied</h2>" +
      "<p>Use the authenticated AQMS account download action.</p>"
    );
}


/* =========================================================
   CONFIGURATION
   ========================================================= */

function config_() {

  return {

    expirationHours:
      Number(
        PropertiesService
          .getScriptProperties()
          .getProperty(
            "APPROVAL_EXPIRATION_HOURS"
          ) || 24
      )
  };
}


/* =========================================================
   DIAGNOSTICS
   ========================================================= */

function diagnosePendingRequestTypes() {
  const sheet = registrySheet_();
  const values = sheet.getDataRange().getValues();

  if (!values || values.length < 2) {
    return {
      ok: true,
      found: false,
      message: "No registry request rows found."
    };
  }

  const headers = values[0];

  for (let r = 1; r < values.length; r++) {
    const row = values[r];

    // STATUS is column 16 = zero-based index 15
    if (String(row[15] || "").trim().toUpperCase() !== "PENDING") {
      continue;
    }

    const fields = [];

    for (let c = 0; c < headers.length; c++) {
      const value = row[c];

      let type = typeof value;
      let objectTag = "";

      try {
        objectTag = Object.prototype.toString.call(value);
      } catch (err) {
        objectTag = "TYPE_CHECK_ERROR";
      }

      fields.push({
        column: c + 1,
        header: String(headers[c] || ""),
        type: type,
        objectTag: objectTag,
        isDate: value instanceof Date,
        isArray: Array.isArray(value),
        isNull: value === null,
        isUndefined: value === undefined,
        isEmptyString: value === "",
        isObject: value !== null && typeof value === "object"
      });
    }

    return {
      ok: true,
      found: true,
      rowNumber: r + 1,
      requestId: String(row[0] || ""),
      status: String(row[15] || ""),
      fieldCount: fields.length,
      fields: fields
    };
  }

  return {
    ok: true,
    found: false,
    message: "No PENDING request found."
  };
}


function diagnoseApprovalSystem() {

  const props =
    PropertiesService
      .getScriptProperties();

  let adminProvisioned =
    false;

  try {

    adminProvisioned =
      Boolean(
        findAdminByUsername_(
          "admin"
        )
      );

  } catch (error) {

    adminProvisioned = false;
  }

  return {

    ok: true,

    serviceUrl:
      ScriptApp.getService()
        .getUrl() || "",

    webAppUrl:
      props.getProperty(
        "WEB_APP_URL"
      ) || "",

    registrySpreadsheetConfigured:
      Boolean(
        props.getProperty(
          "REGISTRY_SPREADSHEET_ID"
        )
      ),

    monitoringSpreadsheetConfigured:
      Boolean(
        props.getProperty(
          "MONITORING_SPREADSHEET_ID"
        )
      ),

    monitoringSheetsConfigured:
      Boolean(
        props.getProperty(
          "MONITORING_SHEETS"
        )
      ),

    adminProvisioned:
      adminProvisioned
  };
}


/* =========================================================
   VERSION
   ========================================================= */

function adminAuthVersion_() {

  return {

    ok: true,

    service:
      "AQMS Approval API",

    version:
      "ADMIN-AUTH-V2",

    authentication:
      "AQMS application username/password",

    requesterLoginRequired:
      false,

    googleIdentityRequiredForAdminLogin:
      false,

    routes: [
      "adminLogin",
      "logout",
      "submit",
      "status",
      "verify",
      "export",
      "exportApprovedRequest",
      "adminSummary",
      "adminRequests",
      "adminRequest",
      "adminDownload",
      "emailPrepared",
      "approve",
      "reject",
      "audit",
      "version"
    ],

    adminPortal:
      "admin.html"
  };
}


/* =========================================================
   SETUP
   ========================================================= */

function setupApprovalRegistry() {

  registrySheet_();
  adminUsersSheet_();
  adminSessionsSheet_();
  auditSheet_();

  return {
    ok: true
  };
}


function setupApprovalSystem(
  webAppUrl
) {

  const properties =
    PropertiesService
      .getScriptProperties();

  const url =
    String(
      webAppUrl ||
      ScriptApp.getService()
        .getUrl() ||
      ""
    ).trim();

  if (url) {

    properties.setProperty(
      "WEB_APP_URL",
      url
    );
  }

  setupApprovalRegistry();

  return diagnoseApprovalSystem();
}


/* =========================================================
   VALIDATION HELPERS
   ========================================================= */

function requiredString_(
  value,
  label
) {

  const text =
    String(
      value || ""
    ).trim();

  if (!text) {

    throw new Error(
      label +
      " is required"
    );
  }

  return text;
}


function normalizeUsername_(
  value
) {

  return String(
    value || ""
  )
    .trim()
    .toLowerCase();
}


/* =========================================================
   PASSWORD HASH
   ========================================================= */

function passwordHash_(
  password,
  salt
) {

  let value =
    String(salt) +
    ":" +
    String(password);

  for (
    let i = 0;
    i < PASSWORD_ITERATIONS;
    i++
  ) {

    value =
      Utilities
        .base64EncodeWebSafe(
          Utilities.computeDigest(
            Utilities.DigestAlgorithm.SHA_256,
            value
          )
        );
  }

  return value;
}


function verifyAdminPassword_(
  password,
  stored
) {

  const separator =
    stored.indexOf("$");

  if (
    separator <= 0
  ) {
    return false;
  }

  const salt =
    stored.slice(
      0,
      separator
    );

  const hash =
    stored.slice(
      separator + 1
    );

  return secureEqual_(
    hash,
    passwordHash_(
      password,
      salt
    )
  );
}


/* =========================================================
   HASH
   ========================================================= */

function hash_(
  value
) {

  return Utilities
    .base64EncodeWebSafe(
      Utilities.computeDigest(
        Utilities.DigestAlgorithm.SHA_256,
        String(value)
      )
    );
}


/* =========================================================
   CONSTANT-TIME COMPARISON
   ========================================================= */

function secureEqual_(
  left,
  right
) {

  const a =
    String(left);

  const b =
    String(right);

  let result =
    a.length ^ b.length;

  const length =
    Math.max(
      a.length,
      b.length
    );

  for (
    let i = 0;
    i < length;
    i++
  ) {

    result |=
      (
        a.charCodeAt(i) || 0
      ) ^
      (
        b.charCodeAt(i) || 0
      );
  }

  return result === 0;
}


/* =========================================================
   JSON RESPONSE
   ========================================================= */

function json_(
  value
) {

  return ContentService
    .createTextOutput(
      JSON.stringify(value)
    )
    .setMimeType(
      ContentService.MimeType.JSON
    );
}