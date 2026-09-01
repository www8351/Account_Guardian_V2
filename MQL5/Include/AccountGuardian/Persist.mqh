//+------------------------------------------------------------------+
//| AccountGuardian - Persist.mqh                                    |
//| Atomic file writes, checksums, halt file (Amendment A1), lock    |
//| state file (Phase 2 Stage 2, design doc item 5), single-instance |
//| mutex heartbeat. SPEC v0.1 sections 3 and 9.                     |
//| Clock exemption (A1): session timestamps and the mutex heartbeat |
//| use TimeLocal; TimeCurrent freezes in dead markets, which would  |
//| fake staleness and make crash timestamps unrecordable offline.   |
//| THE A1 EXEMPTION STOPS AT THE HALT FILE AND THE MUTEX. The lock  |
//| state file's locked_until and breach_time are Q7 (FINAL) fields  |
//| and use TimeCurrent through AgServerNow exclusively; copying the |
//| TimeLocal pattern below into them by analogy is the one mistake  |
//| the design doc names in advance.                                 |
//| No trade calls in this file (static-structure rule, SPEC 1).     |
//+------------------------------------------------------------------+
#ifndef AG_PERSIST_MQH
#define AG_PERSIST_MQH

#include <AccountGuardian/Log.mqh>
#include <AccountGuardian/Clock.mqh>
#include <AccountGuardian/State.mqh>
//--- For AG_PNL_EPSILON. Pnl.mqh includes only Clock.mqh and defines its own
//--- globals, so this pulls in no cycle and no EA-only symbol; the vectors
//--- script, which includes Persist.mqh alone, still compiles standalone.
#include <AccountGuardian/Pnl.mqh>

#define AG_FILES_DIR            "AccountGuardian"
#define AG_HALT_FORMAT_VERSION  1
#define AG_STATE_FORMAT_VERSION 1
#define AG_MAX_SESSIONS         32
#define AG_MUTEX_STALE_SECONDS  10

//--- Money fields are persisted at 8 decimals, not 2. The limit snapshot
//--- is a derived value (base * percent / 100) that carries more precision
//--- than the cent the banner prints: base 1985.97 at 5 percent is 99.2985,
//--- displayed 99.30. Q6 says the locked window is judged by the snapshot,
//--- so rounding it on the way to disk would change the enforced limit on
//--- every restart. The 0.01 epsilon of 2026-07-30 is a comparison rule,
//--- not a storage format.
#define AG_STATE_MONEY_DIGITS   8

// --- halt file in-memory model -------------------------------------
long     g_ag_login = 0;

datetime g_ag_sess_init[AG_MAX_SESSIONS];
bool     g_ag_sess_clean[AG_MAX_SESSIONS];
int      g_ag_sess_count = 0;
int      g_ag_current_session = -1;

bool     g_ag_halt_flag   = false;
string   g_ag_halt_reason = "";
datetime g_ag_halt_time   = 0;

// A save path must never write a model that was never loaded. A refused
// init returns before AgHaltLoad, so the model is default-constructed
// empty, and writing that erases every session record and clears a
// persisted halt flag on disk. See the bypass in SPEC section 7.
bool     g_ag_halt_loaded = false;

// --- mutex ----------------------------------------------------------
double   g_ag_instance_id = 0.0;

// --- lock state file in-memory model (design doc item 5) -------------
// Its own model, mirroring the halt file's, rather than writing State.mqh's
// live globals straight to disk. Stage 3 copies between the two at the one
// point that declares a lock; keeping them separate is what lets this file
// be loaded, quarantined and reset without touching the running state
// machine, which is exactly what the corrupt branch below has to do.
ENUM_AG_LOCK_REASON g_ag_state_reason        = AG_LOCK_NONE;
datetime            g_ag_state_locked_until  = 0;   // Q7: TimeCurrent basis
datetime            g_ag_state_breach_time   = 0;   // Q7: TimeCurrent basis
double              g_ag_state_limit_snap    = 0.0; // Q6 snapshot
double              g_ag_state_base_snap     = 0.0; // Q6 snapshot

// Same obligation as g_ag_halt_loaded, and FINAL in its own right since
// 2026-07-29: "a persistence model that was never loaded is never written",
// stated there as binding beyond the halt file and naming the lock state
// file explicitly.
bool     g_ag_state_loaded = false;

string AgHaltPath()    { return AG_FILES_DIR + "\\halt_" + (string)g_ag_login + ".dat"; }
string AgStatePath()   { return AG_FILES_DIR + "\\state_" + (string)g_ag_login + ".dat"; }
string AgGvHeartbeat() { return "AG_HB_" + (string)g_ag_login; }
string AgGvInstance()  { return "AG_ID_" + (string)g_ag_login; }
string AgGvHaltFlag()  { return "AG_HALT_" + (string)g_ag_login; }
//--- Lock mirror (design doc item 4). Carries a bare locked_until and no
//--- reason, which is why the GV witness defaults to DAILY_BREACH: a GV has
//--- no CORRUPT_STATE concept to express.
string AgGvLock()      { return "AG_LOCK_" + (string)g_ag_login; }

//+------------------------------------------------------------------+
//| FNV-1a over a string. Torn-write detector, not tamper defense:   |
//| forgery is layered against elsewhere (SPEC 4.6, threat model).   |
//+------------------------------------------------------------------+
uint AgChecksum(const string payload)
  {
   uchar bytes[];
   int n = StringToCharArray(payload, bytes, 0, WHOLE_ARRAY, CP_UTF8);
   uint hash = 2166136261;
   for(int i = 0; i < n - 1; i++)   // n-1: skip trailing NUL
     {
      hash ^= (uint)bytes[i];
      hash *= 16777619;
     }
   return hash;
  }

//+------------------------------------------------------------------+
//| Atomic write: tmp, FileFlush, FileMove FILE_REWRITE (SPEC 3).    |
//| Failures are loud and reported to the caller.                    |
//+------------------------------------------------------------------+
bool AgAtomicWrite(const string path, const string content)
  {
   if(!FolderCreate(AG_FILES_DIR))
     {
      if(GetLastError() != 0 && !FileIsExist(path) && GetLastError() != 5019) // 5019: file exists
         AgVerbose("FolderCreate note, error " + (string)GetLastError());
     }
   string tmp = path + ".tmp";
   int handle = FileOpen(tmp, FILE_WRITE | FILE_TXT | FILE_ANSI);
   if(handle == INVALID_HANDLE)
     {
      AgAlertEvent("state-write failure: cannot open " + tmp + ", error " + (string)GetLastError());
      return false;
     }
   FileWriteString(handle, content);
   FileFlush(handle);
   FileClose(handle);
   if(!FileMove(tmp, 0, path, FILE_REWRITE))
     {
      AgAlertEvent("state-write failure: cannot rename " + tmp + " onto " + path + ", error " + (string)GetLastError());
      return false;
     }
   return true;
  }

//+------------------------------------------------------------------+
//| Serialize the halt model. Checksum line last.                    |
//+------------------------------------------------------------------+
string AgHaltSerialize()
  {
   string body = "AGHALT|" + (string)AG_HALT_FORMAT_VERSION + "|" + (string)g_ag_login + "\n";
   for(int i = 0; i < g_ag_sess_count; i++)
      body += "S|" + (string)((long)g_ag_sess_init[i]) + "|" + (g_ag_sess_clean[i] ? "1" : "0") + "\n";
   body += "H|" + (g_ag_halt_flag ? "1" : "0") + "|" + g_ag_halt_reason + "|" + (string)((long)g_ag_halt_time) + "\n";
   body += "C|" + (string)AgChecksum(body) + "\n";
   return body;
  }

bool AgHaltSave()
  {
   return AgAtomicWrite(AgHaltPath(), AgHaltSerialize());
  }

//+------------------------------------------------------------------+
//| Load halt file. Returns: 0 = loaded, 1 = missing, 2 = corrupt.   |
//| Corrupt: quarantine as .bad, loud WARN, model reset (A1 policy:  |
//| fails toward the guardian running, because SAFE_HALT means no    |
//| protection at all).                                              |
//+------------------------------------------------------------------+
int AgHaltLoad()
  {
   g_ag_sess_count = 0;
   g_ag_halt_flag = false;
   g_ag_halt_reason = "";
   g_ag_halt_time = 0;

   // Every exit below leaves a deliberately initialized model: loaded from
   // a valid file, empty because no file exists, or reset after quarantine.
   // All three are legitimate to persist; only never-loaded is not.
   g_ag_halt_loaded = true;

   string path = AgHaltPath();
   if(!FileIsExist(path))
      return 1;

   int handle = FileOpen(path, FILE_READ | FILE_TXT | FILE_ANSI);
   if(handle == INVALID_HANDLE)
     {
      AgWarn("halt file exists but cannot be opened, error " + (string)GetLastError());
      return 2;
     }

   string body = "";
   string checksum_line = "";
   bool ok = false;
   while(!FileIsEnding(handle))
     {
      string line = FileReadString(handle);
      if(StringFind(line, "C|") == 0)
        {
         checksum_line = line;
         ok = true;
         break;
        }
      body += line + "\n";
     }
   FileClose(handle);

   bool valid = ok && (checksum_line == "C|" + (string)AgChecksum(body));
   if(valid)
     {
      string lines[];
      int count = StringSplit(body, '\n', lines);
      if(count < 2 || StringFind(lines[0], "AGHALT|" + (string)AG_HALT_FORMAT_VERSION + "|") != 0)
         valid = false;
      else
        {
         for(int i = 1; i < count; i++)
           {
            string fields[];
            if(StringSplit(lines[i], '|', fields) < 2)
               continue;
            if(fields[0] == "S" && g_ag_sess_count < AG_MAX_SESSIONS)
              {
               g_ag_sess_init[g_ag_sess_count]  = (datetime)StringToInteger(fields[1]);
               g_ag_sess_clean[g_ag_sess_count] = (ArraySize(fields) > 2 && fields[2] == "1");
               g_ag_sess_count++;
              }
            else if(fields[0] == "H" && ArraySize(fields) >= 4)
              {
               g_ag_halt_flag   = (fields[1] == "1");
               g_ag_halt_reason = fields[2];
               g_ag_halt_time   = (datetime)StringToInteger(fields[3]);
              }
           }
        }
     }

   if(!valid)
     {
      string bad = path + ".bad";
      FileMove(path, 0, bad, FILE_REWRITE);
      AgWarn("halt file failed checksum, quarantined as " + bad + ", starting fresh (A1 corruption policy)");
      g_ag_sess_count = 0;
      g_ag_halt_flag = false;
      g_ag_halt_reason = "";
      g_ag_halt_time = 0;
      return 2;
     }
   return 0;
  }

//+------------------------------------------------------------------+
//| Append the current session as unclean; prune to AG_MAX_SESSIONS. |
//+------------------------------------------------------------------+
void AgHaltAppendSession()
  {
   if(g_ag_sess_count >= AG_MAX_SESSIONS)
     {
      for(int i = 1; i < g_ag_sess_count; i++)
        {
         g_ag_sess_init[i - 1]  = g_ag_sess_init[i];
         g_ag_sess_clean[i - 1] = g_ag_sess_clean[i];
        }
      g_ag_sess_count--;
     }
   g_ag_sess_init[g_ag_sess_count]  = TimeLocal();   // A1 clock exemption
   g_ag_sess_clean[g_ag_sess_count] = false;
   g_ag_current_session = g_ag_sess_count;
   g_ag_sess_count++;
  }

//+------------------------------------------------------------------+
//| Consecutive unclean sessions ending at the newest record (R1).    |
//| Walks back from the newest session, which is the current one and  |
//| is unclean by construction, and stops at the first clean record   |
//| or the first adjacent init pair further apart than the bound.     |
//|                                                                   |
//| Anchored on adjacent init pairs, never on "now": that is what     |
//| makes a clean record reset the chain, so routine re-inits cannot  |
//| accumulate toward SAFE_HALT while genuine deaths still do.        |
//|                                                                   |
//| A backward local clock step gives a negative gap, which counts as |
//| inside the bound. Breaking the chain on a negative gap would let  |
//| one clock change disarm the count in a single step, worse than    |
//| the compression residual the SPEC threat model already accepts.   |
//+------------------------------------------------------------------+
int AgHaltUncleanChain(const int max_gap_seconds)
  {
   int chain = 0;
   for(int i = g_ag_sess_count - 1; i >= 0; i--)
     {
      if(g_ag_sess_clean[i])
         break;
      if(i < g_ag_sess_count - 1
         && (long)g_ag_sess_init[i + 1] - (long)g_ag_sess_init[i] > (long)max_gap_seconds)
         break;
      chain++;
     }
   return chain;
  }

void AgHaltMarkClean()
  {
   if(g_ag_current_session >= 0 && g_ag_current_session < g_ag_sess_count)
      g_ag_sess_clean[g_ag_current_session] = true;
  }

void AgHaltSetFlag(const string reason)
  {
   g_ag_halt_flag   = true;
   g_ag_halt_reason = reason;
   g_ag_halt_time   = TimeLocal();   // A1 clock exemption
  }

//+------------------------------------------------------------------+
//| LOCK STATE FILE (Phase 2 Stage 2, design doc item 5, SPEC 3)     |
//|                                                                  |
//| Charter-constrained to lock state only. SAFE_HALT evidence lives |
//| in the halt file and does not belong here (Amendment 2a FINAL:   |
//| "the state file is charter-constrained to lock state only and    |
//| SAFE_HALT is explicitly not a lock"). No freshness field either: |
//| the stale quote ruling of 2026-08-18 makes a snapshot taken from |
//| a frozen quote valid BY DESIGN, so there is nothing to record.   |
//| No floating baseline either, per question FIVE of the same date. |
//+------------------------------------------------------------------+

//+------------------------------------------------------------------+
//| A free quarantine name, never one that would overwrite an        |
//| existing quarantine.                                             |
//|                                                                  |
//| The design doc says to reuse the halt file's plain ".bad" move.  |
//| Deviating deliberately, and the ground is a FINAL entry that     |
//| outranks the convenience: "lock artifacts are never deleted,     |
//| only quarantined" (2026-07-29), which a FileMove FILE_REWRITE    |
//| onto an existing .bad would silently break on the second         |
//| corruption. The halt file's own single-name pattern is left      |
//| exactly as it is; SAFE_HALT evidence is not a lock artifact and  |
//| that path is out of Stage 2's scope.                             |
//+------------------------------------------------------------------+
string AgStateQuarantinePath(const string path)
  {
   string candidate = path + ".bad";
   if(!FileIsExist(candidate))
      return candidate;
   for(int i = 2; i < 1000; i++)
     {
      candidate = path + ".bad." + (string)i;
      if(!FileIsExist(candidate))
         return candidate;
     }
   return path + ".bad.overflow";
  }

//+------------------------------------------------------------------+
//| Serialize the lock state model. Checksum line last, same shape   |
//| as AgHaltSerialize so the two read alike.                        |
//| Magic is AGSTATE, deliberately distinct from AGHALT, so the two  |
//| formats can never cross-read even if the paths were swapped.     |
//+------------------------------------------------------------------+
string AgStateSerialize()
  {
   string body = "AGSTATE|" + (string)AG_STATE_FORMAT_VERSION + "|" + (string)g_ag_login + "\n";
   body += "L|" + (string)(int)g_ag_state_reason
           + "|" + (string)((long)g_ag_state_locked_until)
           + "|" + (string)((long)g_ag_state_breach_time) + "\n";
   body += "N|" + DoubleToString(g_ag_state_limit_snap, AG_STATE_MONEY_DIGITS)
           + "|" + DoubleToString(g_ag_state_base_snap, AG_STATE_MONEY_DIGITS) + "\n";
   body += "C|" + (string)AgChecksum(body) + "\n";
   return body;
  }

//+------------------------------------------------------------------+
//| Write the lock state file. Refuses loudly, never silently, if    |
//| the model was never loaded (FINAL 2026-07-29, binding on this    |
//| file by name). Mirrors the OnDeinit gate on the halt file.       |
//+------------------------------------------------------------------+
bool AgStateSave()
  {
   if(!g_ag_state_loaded)
     {
      AgWarn("state file NOT written: the lock state model was never loaded this session,"
             " so writing it would overwrite a real lock with a default-constructed empty one");
      return false;
     }
   return AgAtomicWrite(AgStatePath(), AgStateSerialize());
  }

void AgStateResetModel()
  {
   g_ag_state_reason       = AG_LOCK_NONE;
   g_ag_state_locked_until = 0;
   g_ag_state_breach_time  = 0;
   g_ag_state_limit_snap   = 0.0;
   g_ag_state_base_snap    = 0.0;
  }

//+------------------------------------------------------------------+
//| Q6 (FINAL): at breach, limit and base are snapshotted here and   |
//| the locked window is judged by the snapshot, never by live       |
//| inputs. Model mutator only, no I/O, mirroring AgHaltSetFlag.     |
//| Both datetimes are TimeCurrent-basis values supplied by the      |
//| caller; this function reads no clock at all, which is what keeps |
//| the A1 TimeLocal exemption out of Q7's fields.                   |
//+------------------------------------------------------------------+
void AgStateSetBreach(const datetime locked_until, const datetime breach_time,
                      const double limit_snapshot, const double base_snapshot)
  {
   g_ag_state_reason       = AG_LOCK_DAILY_BREACH;
   g_ag_state_locked_until = locked_until;
   g_ag_state_breach_time  = breach_time;
   g_ag_state_limit_snap   = limit_snapshot;
   g_ag_state_base_snap    = base_snapshot;
  }

//+------------------------------------------------------------------+
//| CORRUPT_STATE carries no snapshots: there was no breach          |
//| computation behind it, so limit and base are unset rather than   |
//| zero-as-a-value (design doc item 5, "unset/0 for CORRUPT_STATE").|
//+------------------------------------------------------------------+
void AgStateSetCorrupt(const datetime locked_until)
  {
   g_ag_state_reason       = AG_LOCK_CORRUPT_STATE;
   g_ag_state_locked_until = locked_until;
   g_ag_state_breach_time  = 0;
   g_ag_state_limit_snap   = 0.0;
   g_ag_state_base_snap    = 0.0;
  }

//+------------------------------------------------------------------+
//| Quarantine the current file, reset the model to CORRUPT_STATE,   |
//| and write a fresh valid file. Shared by the corrupt branch and   |
//| the login-mismatch branch, which the 2026-07-30 FINAL ruling     |
//| makes the same outcome.                                          |
//|                                                                  |
//| The fresh write is legitimate under never-loaded-never-written   |
//| because g_ag_state_loaded was set true earlier in this same      |
//| call: this is the "reset after quarantine" deliberate            |
//| initialization branch, exactly as AgHaltLoad already does it.    |
//|                                                                  |
//| locked_until is computed NOW from AgServerNow and is never read  |
//| back from the failed file, which is the SPEC's own explicit rule |
//| and the reason a corrupt file cannot dictate its own lock        |
//| window. On a later restart still inside that window this fresh   |
//| file is itself valid and loads cleanly, so there is no           |
//| re-corruption loop.                                              |
//+------------------------------------------------------------------+
int AgStateQuarantine(const string path, const int code, const string why)
  {
   string bad = AgStateQuarantinePath(path);
   if(!FileMove(path, 0, bad, FILE_REWRITE))
      AgWarn("state file quarantine move FAILED onto " + bad + ", error " + (string)GetLastError()
             + "; the fresh CORRUPT_STATE file below will overwrite it in place");
   AgStateSetCorrupt(AgNextDayAnchor(AgServerNow()));
   AgWarn("state file " + why + ", quarantined as " + bad
          + ", locking via CORRUPT_STATE until "
          + TimeToString(g_ag_state_locked_until, TIME_DATE | TIME_SECONDS)
          + " and writing a fresh file");
   AgStateSave();
   return code;
  }

//+------------------------------------------------------------------+
//| Load the lock state file.                                        |
//| Returns: 0 = loaded, 1 = missing, 2 = corrupt, 3 = login         |
//| mismatch. 2 and 3 are handled IDENTICALLY per the FINAL ruling   |
//| of 2026-07-30 that a valid file carrying a foreign login is      |
//| CORRUPT_STATE-equivalent; they are returned distinctly only so   |
//| the caller can say which one happened in the journal.            |
//|                                                                  |
//| Corrupt and mismatch both: quarantine, loud WARN, reset the      |
//| model to CORRUPT_STATE with locked_until = next day anchor       |
//| computed NOW, and write that fresh file. Errs locked and loud.   |
//|                                                                  |
//| Missing is NOT corrupt and NOT trusted as unlocked: the model    |
//| defaults to NONE/0 and the OR-of-three-witnesses formula still   |
//| checks GV and derived history independently (design doc item 4). |
//+------------------------------------------------------------------+
int AgStateLoad()
  {
   AgStateResetModel();

   // Set before the file-exists check, exactly where g_ag_halt_loaded sits.
   // Every exit below leaves a deliberately initialized model: loaded from a
   // valid file, empty because no file exists, or reset after quarantine.
   // All three are legitimate to persist; only never-loaded is not.
   g_ag_state_loaded = true;

   string path = AgStatePath();
   if(!FileIsExist(path))
      return 1;

   int handle = FileOpen(path, FILE_READ | FILE_TXT | FILE_ANSI);
   if(handle == INVALID_HANDLE)
     {
      AgWarn("state file exists but cannot be opened, error " + (string)GetLastError());
      return AgStateQuarantine(path, 2, "cannot be opened");
     }

   string body = "";
   string checksum_line = "";
   bool ok = false;
   while(!FileIsEnding(handle))
     {
      string line = FileReadString(handle);
      if(StringFind(line, "C|") == 0)
        {
         checksum_line = line;
         ok = true;
         break;
        }
      body += line + "\n";
     }
   FileClose(handle);

   bool valid = ok && (checksum_line == "C|" + (string)AgChecksum(body));
   long file_login = 0;
   if(valid)
     {
      string lines[];
      int count = StringSplit(body, '\n', lines);
      string header[];
      if(count < 2
         || StringSplit(lines[0], '|', header) < 3
         || header[0] != "AGSTATE"
         || header[1] != (string)AG_STATE_FORMAT_VERSION)
         valid = false;
      else
        {
         file_login = StringToInteger(header[2]);
         for(int i = 1; i < count; i++)
           {
            string fields[];
            if(StringSplit(lines[i], '|', fields) < 2)
               continue;
            if(fields[0] == "L" && ArraySize(fields) >= 4)
              {
               g_ag_state_reason       = (ENUM_AG_LOCK_REASON)(int)StringToInteger(fields[1]);
               g_ag_state_locked_until = (datetime)StringToInteger(fields[2]);
               g_ag_state_breach_time  = (datetime)StringToInteger(fields[3]);
              }
            else if(fields[0] == "N" && ArraySize(fields) >= 3)
              {
               g_ag_state_limit_snap = StringToDouble(fields[1]);
               g_ag_state_base_snap  = StringToDouble(fields[2]);
              }
           }
        }
     }

   if(!valid)
      return AgStateQuarantine(path, 2, "failed checksum or does not parse");

   //--- A file that is internally valid but belongs to a different account.
   //--- Distinct from the checksum check by design: this project has already
   //--- been bitten once by foreign-project residue sitting at an expected
   //--- path (2026-07-29 residue finding).
   if(file_login != g_ag_login)
      return AgStateQuarantine(path, 3,
                               "carries login " + (string)file_login
                               + " but this account is " + (string)g_ag_login);

   return 0;
  }

//+------------------------------------------------------------------+
//| RATCHET FLOOR FILE (Phase 2 Stage 5, question SEVEN FINAL)       |
//|                                                                  |
//| Its own file rather than a widening of the state file, on         |
//| Amendment 2a's precedent that a separate concern gets a separate  |
//| file rather than widening the charter-constrained lock state.     |
//| The ratchet is not lock state: it governs PRE-BREACH ACTIVE while |
//| Q6's snapshot governs post-breach LOCKED, and the two phases are  |
//| disjoint by construction.                                         |
//|                                                                  |
//| Single scalar, as ratified. `floor_day_anchor` is not a second    |
//| tracked quantity, it is what makes a leftover floor from a prior  |
//| day recognisable as stale rather than silently enforced into a    |
//| new day.                                                          |
//+------------------------------------------------------------------+
#define AG_FLOOR_FORMAT_VERSION 1

datetime g_ag_floor_anchor   = 0;
double   g_ag_floor_currency = 0.0;
bool     g_ag_floor_loaded   = false;   // never-loaded-never-written, same rule

string AgFloorPath() { return AG_FILES_DIR + "\\floor_" + (string)g_ag_login + ".dat"; }

string AgFloorSerialize()
  {
   string body = "AGFLOOR|" + (string)AG_FLOOR_FORMAT_VERSION + "|" + (string)g_ag_login + "\n";
   body += "F|" + (string)((long)g_ag_floor_anchor)
           + "|" + DoubleToString(g_ag_floor_currency, AG_STATE_MONEY_DIGITS) + "\n";
   body += "C|" + (string)AgChecksum(body) + "\n";
   return body;
  }

bool AgFloorSave()
  {
   if(!g_ag_floor_loaded)
     {
      AgWarn("floor file NOT written: the ratchet model was never loaded this session,"
             " so writing it would overwrite a real floor with a default-constructed empty one");
      return false;
     }
   return AgAtomicWrite(AgFloorPath(), AgFloorSerialize());
  }

void AgFloorResetModel()
  {
   g_ag_floor_anchor   = 0;
   g_ag_floor_currency = 0.0;
  }

//+------------------------------------------------------------------+
//| Same quarantine discipline as the state file: a free name, never |
//| overwriting an earlier quarantine, then a reset model. NOTE the  |
//| one difference and it is deliberate: a corrupt floor does NOT     |
//| lock anything. The floor is a pre-breach tightening, not lock     |
//| state, so losing it errs toward the LIVE limit rather than toward |
//| a lock, and the residual that follows, that destroying the floor  |
//| file resets it on the next seed, is the one the 2026-07-30 ruling |
//| already accepted on the record when it built the ratchet.         |
//+------------------------------------------------------------------+
int AgFloorQuarantine(const string path, const int code, const string why)
  {
   string bad = AgStateQuarantinePath(path);
   if(!FileMove(path, 0, bad, FILE_REWRITE))
      AgWarn("floor file quarantine move FAILED onto " + bad + ", error " + (string)GetLastError());
   AgFloorResetModel();
   AgWarn("floor file " + why + ", quarantined as " + bad
          + ", the ratchet reseeds from the live limit on the next completed pass"
          + " (no lock follows: the floor is not lock state)");
   AgFloorSave();
   return code;
  }

//+------------------------------------------------------------------+
//| Returns: 0 = loaded, 1 = missing, 2 = corrupt, 3 = login         |
//| mismatch. Same shape and the same discipline as AgStateLoad.     |
//+------------------------------------------------------------------+
int AgFloorLoad()
  {
   AgFloorResetModel();
   g_ag_floor_loaded = true;   // before the exists check, as for the halt and state models

   string path = AgFloorPath();
   if(!FileIsExist(path))
      return 1;

   int handle = FileOpen(path, FILE_READ | FILE_TXT | FILE_ANSI);
   if(handle == INVALID_HANDLE)
     {
      AgWarn("floor file exists but cannot be opened, error " + (string)GetLastError());
      return AgFloorQuarantine(path, 2, "cannot be opened");
     }

   string body = "";
   string checksum_line = "";
   bool ok = false;
   while(!FileIsEnding(handle))
     {
      string line = FileReadString(handle);
      if(StringFind(line, "C|") == 0)
        {
         checksum_line = line;
         ok = true;
         break;
        }
      body += line + "\n";
     }
   FileClose(handle);

   bool valid = ok && (checksum_line == "C|" + (string)AgChecksum(body));
   long file_login = 0;
   if(valid)
     {
      string lines[];
      int count = StringSplit(body, '\n', lines);
      string header[];
      if(count < 2
         || StringSplit(lines[0], '|', header) < 3
         || header[0] != "AGFLOOR"
         || header[1] != (string)AG_FLOOR_FORMAT_VERSION)
         valid = false;
      else
        {
         file_login = StringToInteger(header[2]);
         for(int i = 1; i < count; i++)
           {
            string fields[];
            if(StringSplit(lines[i], '|', fields) < 3)
               continue;
            if(fields[0] == "F")
              {
               g_ag_floor_anchor   = (datetime)StringToInteger(fields[1]);
               g_ag_floor_currency = StringToDouble(fields[2]);
              }
           }
        }
     }

   if(!valid)
      return AgFloorQuarantine(path, 2, "failed checksum or does not parse");
   if(file_login != g_ag_login)
      return AgFloorQuarantine(path, 3,
                               "carries login " + (string)file_login
                               + " but this account is " + (string)g_ag_login);
   return 0;
  }

//+------------------------------------------------------------------+
//| The enforced limit while ACTIVE: min(live limit, same-day floor).|
//| PRE-BREACH ONLY, as ratified. A floor whose day anchor is not    |
//| today's is STALE and contributes nothing, which is the case of a |
//| floor file left over from a prior day that no pass has reseeded  |
//| because the EA has not run a tick since the rollover.            |
//|                                                                  |
//| Nothing in LOCKED calls this. Q6's snapshot governs the locked   |
//| window unconditionally and the floor never touches it.           |
//+------------------------------------------------------------------+
double AgFloorEffectiveLimit(const double live_limit, const datetime window_anchor)
  {
   //--- A floor belonging to an EARLIER day is stale and contributes nothing:
   //--- that is a leftover file no pass has reseeded because the EA has not
   //--- run a tick since the rollover, and enforcing it would carry one day's
   //--- tightening into the next.
   //--- A floor belonging to the SAME day applies, which is the ordinary case.
   //--- A floor belonging to a LATER day also applies, and that is deliberate
   //--- rather than an oversight: it is what a backward clock step produces,
   //--- and keeping the tighter value enforced is the strict direction. The
   //--- alternative, treating it as stale, would let one clock rewind drop the
   //--- floor in a single act, which is precisely the one-step disarm the NO
   //--- RESEED ON A BACKWARD STEP clause exists to prevent.
   if(g_ag_floor_anchor < window_anchor || g_ag_floor_currency <= 0.0)
      return live_limit;
   return (g_ag_floor_currency < live_limit) ? g_ag_floor_currency : live_limit;
  }

//--- Cadence for the hold and backward-step WARNs, local clock, A1 class.
datetime g_ag_last_ratchet_warn = 0;

//--- MOVED HERE FROM THE EA, applying the owner ruling of 2026-08-18 that
//--- put the locked_until bound helpers in Clock.mqh for the same reason:
//--- a script cannot include an EA, so while this lived there the six
//--- vectors question SEVEN calls for could not be written at all. The
//--- WARN cadence arrives as a parameter rather than by moving the EA's
//--- AG_LIFE_INTERVAL_SECONDS constant, which keeps Phase 1 untouched.
//+------------------------------------------------------------------+
//| THE RATCHET (Phase 2 Stage 5, question SEVEN FINAL 2026-08-18).  |
//| Defends against ACTIVE-state limit inflation: raising a limit    |
//| input after the day has started but before any breach.           |
//|                                                                  |
//| The ratcheted quantity is the DERIVED limit_currency and not the |
//| raw inputs, which is the correction the 2026-07-30 addendum made |
//| and the ruling ratified. Under Q8's min-of-enabled a leg that is |
//| not binding can be disabled with zero effect on the enforced     |
//| limit, and an input-level ratchet blocks that as a false         |
//| positive; the owner's worked case is base 2000 with percent 5    |
//| giving 100 and currency 50 binding, where disabling the percent  |
//| leg moves nothing.                                               |
//|                                                                  |
//| PRE-BREACH ONLY. This is called from the breach tail and from    |
//| nowhere else. Q6's snapshot governs the locked window            |
//| unconditionally and the floor never touches it, so the two are   |
//| disjoint by construction rather than by care.                    |
//|                                                                  |
//| Returns the limit to enforce this pass.                          |
//+------------------------------------------------------------------+
double AgRatchetUpdate(const datetime window_anchor, const double live_limit,
                       const int warn_cadence_seconds)
  {
   if(!g_ag_floor_loaded)
      return live_limit;   // never loaded, never written; enforce live and say nothing

   //--- SEED: first completed ACTIVE computation with no floor at all.
   if(g_ag_floor_anchor == 0)
     {
      g_ag_floor_anchor   = window_anchor;
      g_ag_floor_currency = live_limit;
      AgFloorSave();
      AgInfo("ratchet seeded|anchor=" + TimeToString(window_anchor, TIME_DATE | TIME_SECONDS)
             + "|floor=" + DoubleToString(live_limit, 2));
      return live_limit;
     }

   //--- RESEED AT ROLLOVER: the anchor advanced, so the new day starts from
   //--- whatever the live limit is now. This is the only reseed there is.
   if(window_anchor > g_ag_floor_anchor)
     {
      AgInfo("ratchet reseeded at rollover|old_anchor="
             + TimeToString(g_ag_floor_anchor, TIME_DATE | TIME_SECONDS)
             + "|new_anchor=" + TimeToString(window_anchor, TIME_DATE | TIME_SECONDS)
             + "|old_floor=" + DoubleToString(g_ag_floor_currency, 2)
             + "|new_floor=" + DoubleToString(live_limit, 2));
      g_ag_floor_anchor   = window_anchor;
      g_ag_floor_currency = live_limit;
      AgFloorSave();
      return live_limit;
     }

   //--- NO RESEED ON A BACKWARD STEP. The floor belongs to a LATER day than
   //--- the one being computed, which is what a rewound clock produces.
   //--- Reseeding here would hand a one-act reset to anyone able to move the
   //--- clock back once, the same class of one-step disarm the 2026-08-04
   //--- negative-gap ruling refused in the crash-loop chain. The floor is
   //--- held AND stays enforced, which is the strict direction.
   if(window_anchor < g_ag_floor_anchor)
     {
      datetime now_local_back = TimeLocal();
      if(g_ag_last_ratchet_warn == 0
         || now_local_back - g_ag_last_ratchet_warn >= warn_cadence_seconds)
        {
         AgWarn("ratchet NOT reseeded on a backward clock step: window anchor "
                + TimeToString(window_anchor, TIME_DATE | TIME_SECONDS)
                + " is behind the floor's anchor "
                + TimeToString(g_ag_floor_anchor, TIME_DATE | TIME_SECONDS)
                + "; floor " + DoubleToString(g_ag_floor_currency, 2) + " is held and still enforced");
         g_ag_last_ratchet_warn = now_local_back;
        }
      return AgFloorEffectiveLimit(live_limit, window_anchor);
     }

   //--- SAME DAY. Lower on a decrease, hold on an increase.
   //--- BOTH TESTS GO THROUGH AG_PNL_EPSILON (owner ruling 2026-08-18, taken
   //--- after the live Stage 7 finding). g_ag_floor_currency arrives at this
   //--- line by two different routes: straight out of AgLimitCurrency in the
   //--- session that seeded it, or through AgFloorSerialize's 8-decimal
   //--- DoubleToString and back through StringToDouble in every session after
   //--- a restart. Those two routes are not required to yield the same double,
   //--- and an exact < or > promotes a difference below the last written digit
   //--- into a branch decision. That is what fired 220 times on the live
   //--- account between 02:01 and 10:39 on 2026-08-18, reporting a raised limit
   //--- nobody had raised. The band is one cent wide and its cost is stated
   //--- rather than hidden: a real limit change smaller than a cent now moves
   //--- neither the floor nor the journal.
   if(live_limit < g_ag_floor_currency - AG_PNL_EPSILON)
     {
      g_ag_floor_currency = live_limit;   // running minimum
      AgFloorSave();
     }
   else if(live_limit > g_ag_floor_currency + AG_PNL_EPSILON)
     {
      datetime now_local_hold = TimeLocal();
      if(g_ag_last_ratchet_warn == 0
         || now_local_hold - g_ag_last_ratchet_warn >= warn_cadence_seconds)
        {
         AgWarn("ratchet HOLDING against a raised limit (question SEVEN): live="
                + DoubleToString(live_limit, 2) + " floor="
                + DoubleToString(g_ag_floor_currency, 2)
                + "; the floor is enforced until the next day anchor");
         g_ag_last_ratchet_warn = now_local_hold;
        }
     }
   return AgFloorEffectiveLimit(live_limit, window_anchor);
  }

//+------------------------------------------------------------------+
//| REALIZED PEAK FILE (version 1 of the realized peak trailing      |
//| floor, ruling set D1 through D8 FINAL 2026-08-24)                |
//|                                                                  |
//| Its own file, `peak_<login>.dat`, written through AgAtomicWrite, |
//| exactly as D6 ruled and for the same reason the ratchet floor    |
//| above got one: `floor_<login>.dat` STAYS BYTE IDENTICAL to what  |
//| is deployed today, and question SEVEN is not superseded in any   |
//| clause. `state_<login>.dat` and AG_STATE_FORMAT_VERSION are      |
//| likewise untouched, per D8 and the two FINAL rulings of          |
//| 2026-08-20.                                                      |
//|                                                                  |
//| THE ONE DELIBERATE DIFFERENCE FROM THE FLOOR BLOCK ABOVE, and it |
//| is the whole of what D3.1 changes: a corrupt or missing floor    |
//| RESEEDS from the live limit, while a corrupt or missing peak     |
//| RECONSTRUCTS FROM TODAY'S DEAL HISTORY. Broker history is the    |
//| source of truth for the peak and this file is a CROSS CHECK      |
//| ONLY, so losing it costs nothing that the next completed pass    |
//| cannot rebuild, and nothing here ever seeds a peak from an       |
//| input. `peak_day_anchor` is not a second tracked quantity, it is |
//| what makes a leftover peak from a prior day recognisable as      |
//| stale, the same job it does for the floor.                       |
//|                                                                  |
//| PRE-BREACH ONLY, per D8. Nothing in LOCKED calls anything in     |
//| this block. Q6's snapshot governs the locked window              |
//| unconditionally and the peak never touches it, exactly as the    |
//| ratchet never does.                                              |
//+------------------------------------------------------------------+
#define AG_PEAK_FORMAT_VERSION 1

datetime g_ag_peak_anchor     = 0;
double   g_ag_peak_currency   = 0.0;   // the day's realized high water mark
bool     g_ag_peak_loaded     = false; // never-loaded-never-written, same rule
bool     g_ag_peak_reconciled = false; // the D3.1 reconciliation runs once per session

//--- Cadence for the backward-step WARN, local clock, A1 class. Its own
//--- cadence rather than a share of the ratchet's: two mechanisms holding
//--- against the same rewound clock must each be able to say so, or the
//--- artifact records one of them and leaves the other looking silent.
datetime g_ag_last_peak_warn = 0;

string AgPeakPath() { return AG_FILES_DIR + "\\peak_" + (string)g_ag_login + ".dat"; }

string AgPeakSerialize()
  {
   string body = "AGPEAK|" + (string)AG_PEAK_FORMAT_VERSION + "|" + (string)g_ag_login + "\n";
   body += "P|" + (string)((long)g_ag_peak_anchor)
           + "|" + DoubleToString(g_ag_peak_currency, AG_STATE_MONEY_DIGITS) + "\n";
   body += "C|" + (string)AgChecksum(body) + "\n";
   return body;
  }

bool AgPeakSave()
  {
   if(!g_ag_peak_loaded)
     {
      AgWarn("peak file NOT written: the realized peak model was never loaded this session,"
             " so writing it would overwrite a real peak with a default-constructed empty one");
      return false;
     }
   return AgAtomicWrite(AgPeakPath(), AgPeakSerialize());
  }

void AgPeakResetModel()
  {
   g_ag_peak_anchor   = 0;
   g_ag_peak_currency = 0.0;
  }

//+------------------------------------------------------------------+
//| Same quarantine discipline as the state and floor files: a free  |
//| name, never overwriting an earlier quarantine, then a reset      |
//| model. A corrupt peak does NOT lock anything and does NOT        |
//| reseed: the peak is a pre-breach tightening rather than lock     |
//| state, and D3.1 makes deal history its source of truth, so the   |
//| next completed ACTIVE pass RECONSTRUCTS it. That is a strictly   |
//| smaller residual than the floor's, whose reseed genuinely does   |
//| lose a day's tightening when the file is destroyed.              |
//+------------------------------------------------------------------+
int AgPeakQuarantine(const string path, const int code, const string why)
  {
   string bad = AgStateQuarantinePath(path);
   if(!FileMove(path, 0, bad, FILE_REWRITE))
      AgWarn("peak file quarantine move FAILED onto " + bad + ", error " + (string)GetLastError());
   AgPeakResetModel();
   AgWarn("peak file " + why + ", quarantined as " + bad
          + ", the realized peak RECONSTRUCTS from today's deal history on the next completed"
          + " pass and is never reseeded from an input (no lock follows: the peak is not lock state)");
   AgPeakSave();
   return code;
  }

//+------------------------------------------------------------------+
//| Returns: 0 = loaded, 1 = missing, 2 = corrupt, 3 = login         |
//| mismatch. Same shape and the same discipline as AgFloorLoad.     |
//| What is loaded here is a CROSS CHECK and never an authority: the |
//| first ACTIVE pass reconciles it against a reconstruction and     |
//| that reconciliation, not this load, decides the peak (D3.1).     |
//+------------------------------------------------------------------+
int AgPeakLoad()
  {
   AgPeakResetModel();
   g_ag_peak_loaded = true;   // before the exists check, as for every model above

   string path = AgPeakPath();
   if(!FileIsExist(path))
      return 1;

   int handle = FileOpen(path, FILE_READ | FILE_TXT | FILE_ANSI);
   if(handle == INVALID_HANDLE)
     {
      AgWarn("peak file exists but cannot be opened, error " + (string)GetLastError());
      return AgPeakQuarantine(path, 2, "cannot be opened");
     }

   string body = "";
   string checksum_line = "";
   bool ok = false;
   while(!FileIsEnding(handle))
     {
      string line = FileReadString(handle);
      if(StringFind(line, "C|") == 0)
        {
         checksum_line = line;
         ok = true;
         break;
        }
      body += line + "\n";
     }
   FileClose(handle);

   bool valid = ok && (checksum_line == "C|" + (string)AgChecksum(body));
   long file_login = 0;
   if(valid)
     {
      string lines[];
      int count = StringSplit(body, '\n', lines);
      string header[];
      if(count < 2
         || StringSplit(lines[0], '|', header) < 3
         || header[0] != "AGPEAK"
         || header[1] != (string)AG_PEAK_FORMAT_VERSION)
         valid = false;
      else
        {
         file_login = StringToInteger(header[2]);
         for(int i = 1; i < count; i++)
           {
            string fields[];
            if(StringSplit(lines[i], '|', fields) < 3)
               continue;
            if(fields[0] == "P")
              {
               g_ag_peak_anchor   = (datetime)StringToInteger(fields[1]);
               g_ag_peak_currency = StringToDouble(fields[2]);
              }
           }
        }
     }

   if(!valid)
      return AgPeakQuarantine(path, 2, "failed checksum or does not parse");
   if(file_login != g_ag_login)
      return AgPeakQuarantine(path, 3,
                              "carries login " + (string)file_login
                              + " but this account is " + (string)g_ag_login);
   return 0;
  }

//+------------------------------------------------------------------+
//| The peak term of the lock level: realized peak minus the POST    |
//| RATCHET enforced_limit (D7), never the raw live limit.           |
//|                                                                  |
//| The staleness rules are the floor's, deliberately and to the     |
//| letter, because they answer the same three clock cases. A peak   |
//| belonging to an EARLIER day is stale and contributes nothing,    |
//| which is a leftover file no pass has reconciled because the EA   |
//| has not run a tick since the rollover. A peak belonging to the   |
//| SAME day applies, the ordinary case. A peak belonging to a LATER |
//| day also applies, which is what a backward clock step produces,  |
//| and keeping the tighter value enforced is the strict direction   |
//| for the identical reason the floor gives: the alternative hands  |
//| a one-step disarm to anyone able to move the clock back once.    |
//|                                                                  |
//| A peak of zero contributes nothing, which is not a special case  |
//| but the arithmetic: peak - enforced_limit is then exactly        |
//| -enforced_limit, the ratchet term, and MathMax at the call site  |
//| sees a tie.                                                      |
//+------------------------------------------------------------------+
double AgPeakEffectiveLevel(const double enforced_limit, const datetime window_anchor)
  {
   if(g_ag_peak_anchor < window_anchor || g_ag_peak_currency <= 0.0)
      return -enforced_limit;
   return g_ag_peak_currency - enforced_limit;
  }

//+------------------------------------------------------------------+
//| THE REALIZED PEAK (version 1, D1 through D8 FINAL 2026-08-24).   |
//| Called from the breach tail beside AgRatchetUpdate and from      |
//| nowhere else, so it inherits that region's PRE-BREACH ONLY       |
//| constraint and the Q10, Q10 amendment, Q8 and Q9 guards above it |
//| rather than restating any of them.                               |
//|                                                                  |
//| Returns peak_level, the peak term of the lock level. The caller  |
//| takes MathMax against the ratchet term, which is D2: stricter    |
//| always wins, in every scenario, no exceptions.                   |
//|                                                                  |
//| THE PEAK IS RECONSTRUCTED FROM DEAL HISTORY ON EVERY PASS, not   |
//| accumulated across passes, which is D3.1 applied uniformly       |
//| rather than only at boot. A pass that samples the cumulative     |
//| realized cannot see a dip and recovery that happened between two |
//| samples, while the running maximum inside the sorted walk sees   |
//| every deal in order, and reconstructing everywhere means the     |
//| restart path is the ordinary path and gets no separate code to   |
//| be wrong on its own. The cost is stated rather than hidden: this |
//| adds one more call into the same fold AgRealized already runs    |
//| each pass. It is a second CALL and not a second WALK, the fold   |
//| itself existing once in Pnl.mqh with the F12 whitelist and the   |
//| Q3 formula written down once, which is what the defect 3 shape 1 |
//| FINAL of 2026-08-20 protects.                                    |
//|                                                                  |
//| It runs AFTER the caller has read HistoryDealsTotal for the Q9   |
//| deferral, deliberately: the fold re-selects the same window with |
//| the same anchor, so the count is unchanged either way, and the   |
//| ordering keeps the Q9 reading provably the one Phase 1 took.     |
//+------------------------------------------------------------------+
double AgPeakUpdate(const datetime window_anchor, const double enforced_limit,
                    const int warn_cadence_seconds)
  {
   if(!g_ag_peak_loaded)
      return -enforced_limit;   // never loaded, never written; the peak says nothing

   //--- RECONSTRUCT. Broker history is the source of truth (D3.1) and the
   //--- persisted value below is only ever weighed against this.
   bool     ok            = true;
   double   discard_min   = 0.0;
   double   reconstructed = 0.0;
   ulong    max_ticket    = 0;
   datetime max_time      = 0;
   AgRealizedRunFold(window_anchor, ok, discard_min, reconstructed, max_ticket, max_time);
   if(!ok)
     {
      //--- F6: a false HistorySelect is a stability failure and never zero
      //--- deals. The fold has already logged it loudly. The model is left
      //--- exactly as it stands and the level it already implies is still
      //--- enforced, which holds rather than loosens.
      return AgPeakEffectiveLevel(enforced_limit, window_anchor);
     }

   //--- FIRST ACTIVE PASS OF THE SESSION: the D3.1 reconciliation, whose four
   //--- cases are the four this table names. The persisted value is a cross
   //--- check in every one of them and the authority in none.
   if(!g_ag_peak_reconciled)
     {
      double taken  = reconstructed;
      string source = "no_file";
      if(g_ag_peak_anchor == 0)
        {
         taken  = reconstructed;             // nothing on disk: reconstruction stands alone
         source = "no_file";
        }
      else if(g_ag_peak_anchor == window_anchor)
        {
         taken  = MathMax(g_ag_peak_currency, reconstructed);   // mismatch: stricter of the two
         source = "equal_anchor_max";
        }
      else if(g_ag_peak_anchor < window_anchor)
        {
         taken  = reconstructed;             // a prior day's peak is stale, not stricter
         source = "stale_anchor_reconstructed";
        }
      else
        {
         taken  = MathMax(g_ag_peak_currency, reconstructed);   // backward clock step
         source = "backward_step_max";
        }

      AgInfo("realized peak reconciled|anchor="
             + TimeToString(window_anchor, TIME_DATE | TIME_SECONDS)
             + "|reconstructed=" + DoubleToString(reconstructed, 2)
             + "|persisted=" + DoubleToString(g_ag_peak_currency, 2)
             + "|taken=" + DoubleToString(taken, 2)
             + "|source=" + source);

      //--- The anchor moves FORWARD ONLY. On the backward-step case the peak's
      //--- anchor is held at the later day, so a clock rewind cannot turn the
      //--- correction back into a rollover and reset the peak in one act; that
      //--- is the ratchet's NO RESEED ON A BACKWARD STEP clause applied here.
      if(window_anchor > g_ag_peak_anchor)
         g_ag_peak_anchor = window_anchor;
      g_ag_peak_currency   = taken;
      g_ag_peak_reconciled = true;
      AgPeakSave();
      return AgPeakEffectiveLevel(enforced_limit, window_anchor);
     }

   //--- ROLLOVER. There is NO RESET ACTION here and none is wanted: the walk's
   //--- window moved with the anchor, so `reconstructed` is already the new
   //--- day's running maximum starting from zero. All this branch does is
   //--- re-stamp the anchor and say so in the journal (D3.2, and the Reason of
   //--- the same FINAL, which records that the reset is the window moving).
   if(window_anchor > g_ag_peak_anchor)
     {
      AgInfo("realized peak reset at rollover|old_anchor="
             + TimeToString(g_ag_peak_anchor, TIME_DATE | TIME_SECONDS)
             + "|new_anchor=" + TimeToString(window_anchor, TIME_DATE | TIME_SECONDS)
             + "|old_peak=" + DoubleToString(g_ag_peak_currency, 2)
             + "|new_peak=" + DoubleToString(reconstructed, 2));
      g_ag_peak_anchor   = window_anchor;
      g_ag_peak_currency = reconstructed;
      AgPeakSave();
      return AgPeakEffectiveLevel(enforced_limit, window_anchor);
     }

   //--- NO REWIND ON A BACKWARD STEP, the ratchet's clause applied to the peak.
   //--- The peak is HELD and stays enforced. It is not raised from this pass's
   //--- reconstruction either, and that is the point rather than an oversight:
   //--- a rewound anchor widens the walk's window into the previous day, so the
   //--- running maximum it returns is a two-day figure and tightening on it
   //--- would enforce a peak that no single day ever reached. Holding does not
   //--- loosen anything, so D2 is untouched: D2 governs the max BETWEEN the two
   //--- mechanisms, and neither term moves down here.
   if(window_anchor < g_ag_peak_anchor)
     {
      datetime now_local_back = TimeLocal();
      if(g_ag_last_peak_warn == 0
         || now_local_back - g_ag_last_peak_warn >= warn_cadence_seconds)
        {
         AgWarn("realized peak NOT rewound on a backward clock step: window anchor "
                + TimeToString(window_anchor, TIME_DATE | TIME_SECONDS)
                + " is behind the peak's anchor "
                + TimeToString(g_ag_peak_anchor, TIME_DATE | TIME_SECONDS)
                + "; peak " + DoubleToString(g_ag_peak_currency, 2)
                + " is held and still enforced, and is not raised from a widened window");
         g_ag_last_peak_warn = now_local_back;
        }
      return AgPeakEffectiveLevel(enforced_limit, window_anchor);
     }

   //--- SAME DAY. Monotone: it rises or it stays (D1.3). There is no lowering
   //--- branch anywhere in this function, which is what makes a losing deal
   //--- after a gain leave the floor exactly where the gain put it.
   //--- THE RISE TEST GOES THROUGH AG_PNL_EPSILON, per the ratchet epsilon
   //--- FINAL of 2026-08-18 and for its reason rather than by analogy:
   //--- g_ag_peak_currency reaches this line by two routes, straight out of
   //--- the fold in the pass that set it, or through AgPeakSerialize's
   //--- 8-decimal DoubleToString and back through StringToDouble after a
   //--- restart, and those two routes are not required to yield the same
   //--- double. An exact > would promote a difference below the last written
   //--- digit into a journal line and a file write on every pass, which is the
   //--- shape of the 220 spurious lines the ratchet produced on 2026-08-18.
   if(reconstructed > g_ag_peak_currency + AG_PNL_EPSILON)
     {
      AgInfo("realized peak raised|anchor="
             + TimeToString(window_anchor, TIME_DATE | TIME_SECONDS)
             + "|old=" + DoubleToString(g_ag_peak_currency, 2)
             + "|new=" + DoubleToString(reconstructed, 2)
             + "|deal_ticket=" + (string)max_ticket
             + "|deal_time=" + TimeToString(max_time, TIME_DATE | TIME_SECONDS));
      g_ag_peak_currency = reconstructed;
      AgPeakSave();
     }
   return AgPeakEffectiveLevel(enforced_limit, window_anchor);
  }

//+------------------------------------------------------------------+
//| EQUITY PEAK FILE (version 2 of the trailing floor, ruling set     |
//| V2-D1 through V2-D18 FINAL 2026-09-01)                           |
//|                                                                  |
//| A THIRD FILE, `equity_<login>.dat`, with its own format constant |
//| starting at 1, exactly as V2-D8 ruled. `peak_<login>.dat` and    |
//| AG_PEAK_FORMAT_VERSION are UNTOUCHED, so no migration branch     |
//| exists anywhere on the version 1 file; `floor_<login>.dat` stays |
//| byte identical per D6; `state_<login>.dat` and                    |
//| AG_STATE_FORMAT_VERSION are untouched per V2-D11.                |
//|                                                                  |
//| WHAT THIS FILE HOLDS, and it is the whole of what version 2 adds:|
//| the running maximum of `pnl`, realized plus floating, sampled on |
//| the ACTIVE pass per V2-D2. The realized peak above is raised by  |
//| closures alone; this one is raised by the same quantity the      |
//| breach comparison already uses, which is what makes an unrealized|
//| high that is given back catchable. V2-D1 supersedes the "floating|
//| profit NEVER raises it" clause of D1.1 BY NAME and narrowly, and |
//| only in this repository; the realized peak block above is        |
//| untouched and remains realized only, per V2-D6's "the realized   |
//| peak is not subsumed".                                           |
//|                                                                  |
//| WHAT IT INHERITS BY NAME (V2-D8): never loaded never written     |
//| (2026-07-29); login mismatch is CORRUPT_STATE equivalent         |
//| (2026-07-30); the anchor lives in the record so a stale one is   |
//| recognisable; and the reconciliation line mirrors the realized   |
//| peak's, source field included.                                   |
//|                                                                  |
//| THE ONE DELIBERATE DIFFERENCE FROM THE STATE FAMILY, and it is   |
//| the floor and peak blocks' difference rather than a new one: a   |
//| corrupt or foreign equity file LOCKS NOTHING. Under V2-D4 it     |
//| degrades to the realized peak, that is to version 1 authority,   |
//| never to nothing and never to a lock. The equity file is not     |
//| lock state.                                                      |
//|                                                                  |
//| PRE BREACH ONLY, per V2-D11, exactly as the ratchet and the      |
//| realized peak are. Nothing in LOCKED and nothing in the boot     |
//| derivation calls anything in this block.                         |
//+------------------------------------------------------------------+
#define AG_EQUITY_FORMAT_VERSION 1

datetime g_ag_equity_anchor = 0;
double   g_ag_equity_peak   = 0.0;   // the day's running maximum of pnl
bool     g_ag_equity_loaded = false; // never-loaded-never-written, same rule

string AgEquityPath() { return AG_FILES_DIR + "\\equity_" + (string)g_ag_login + ".dat"; }

//+------------------------------------------------------------------+
//| Magic is AGEQUITY, distinct from the magic of every one of the   |
//| four files above it, so no two of the five formats can ever      |
//| cross-read even if their paths were swapped. The four are not    |
//| spelled here deliberately: the version 2 acceptance check greps  |
//| this diff for their magics to prove their serializers are byte   |
//| identical, and a mention in a comment would trip it.             |
//| Money at AG_STATE_MONEY_DIGITS and                               |
//| never at the printed cent: V2-D6 subtracts the enforced limit    |
//| from this value to form equity_level and the breach comparison   |
//| runs under a one cent epsilon one line later, so rounding on the |
//| way to disk would move the enforced level on every restart.      |
//+------------------------------------------------------------------+
string AgEquitySerialize()
  {
   string body = "AGEQUITY|" + (string)AG_EQUITY_FORMAT_VERSION + "|" + (string)g_ag_login + "\n";
   body += "E|" + (string)((long)g_ag_equity_anchor)
           + "|" + DoubleToString(g_ag_equity_peak, AG_STATE_MONEY_DIGITS) + "\n";
   body += "C|" + (string)AgChecksum(body) + "\n";
   return body;
  }

bool AgEquitySave()
  {
   if(!g_ag_equity_loaded)
     {
      AgWarn("equity file NOT written: the equity peak model was never loaded this session,"
             " so writing it would overwrite a real peak with a default-constructed empty one");
      return false;
     }
   return AgAtomicWrite(AgEquityPath(), AgEquitySerialize());
  }

void AgEquityResetModel()
  {
   g_ag_equity_anchor = 0;
   g_ag_equity_peak   = 0.0;
  }

//+------------------------------------------------------------------+
//| Same quarantine discipline as the state, floor and peak files: a |
//| free name, never overwriting an earlier quarantine, then a reset |
//| model and a fresh valid file.                                    |
//|                                                                  |
//| NO LOCK FOLLOWS, which is the floor and peak behaviour and not   |
//| the state file's. V2-D4 names the outcome for this file          |
//| precisely: a missing, corrupt, login-mismatched or stale-anchor  |
//| file DEGRADES TO THE REALIZED PEAK, never to nothing. So losing  |
//| this file costs the excess of the equity peak over the realized  |
//| peak for the day and nothing else, and the guardian falls back   |
//| to exactly the version 1 authority the realized peak block above |
//| already provides.                                                |
//+------------------------------------------------------------------+
int AgEquityQuarantine(const string path, const int code, const string why)
  {
   string bad = AgStateQuarantinePath(path);
   if(!FileMove(path, 0, bad, FILE_REWRITE))
      AgWarn("equity file quarantine move FAILED onto " + bad + ", error " + (string)GetLastError());
   AgEquityResetModel();
   AgWarn("equity file " + why + ", quarantined as " + bad
          + ", the equity peak DEGRADES to the realized peak for this day and is never seeded"
          + " from an input (no lock follows: the equity peak is not lock state)");
   AgEquitySave();
   return code;
  }

//+------------------------------------------------------------------+
//| Returns: 0 = loaded, 1 = missing, 2 = corrupt, 3 = login         |
//| mismatch. Same shape and the same discipline as AgPeakLoad.      |
//| What is loaded here is weighed and never obeyed: the first       |
//| ACTIVE pass reconciles it against the realized peak and the      |
//| in-memory peak, and that reconciliation decides the value        |
//| (V2-D4, as scoped by V2-D15).                                    |
//+------------------------------------------------------------------+
int AgEquityLoad()
  {
   AgEquityResetModel();
   g_ag_equity_loaded = true;   // before the exists check, as for every model above

   string path = AgEquityPath();
   if(!FileIsExist(path))
      return 1;

   int handle = FileOpen(path, FILE_READ | FILE_TXT | FILE_ANSI);
   if(handle == INVALID_HANDLE)
     {
      AgWarn("equity file exists but cannot be opened, error " + (string)GetLastError());
      return AgEquityQuarantine(path, 2, "cannot be opened");
     }

   string body = "";
   string checksum_line = "";
   bool ok = false;
   while(!FileIsEnding(handle))
     {
      string line = FileReadString(handle);
      if(StringFind(line, "C|") == 0)
        {
         checksum_line = line;
         ok = true;
         break;
        }
      body += line + "\n";
     }
   FileClose(handle);

   bool valid = ok && (checksum_line == "C|" + (string)AgChecksum(body));
   long file_login = 0;
   if(valid)
     {
      string lines[];
      int count = StringSplit(body, '\n', lines);
      string header[];
      if(count < 2
         || StringSplit(lines[0], '|', header) < 3
         || header[0] != "AGEQUITY"
         || header[1] != (string)AG_EQUITY_FORMAT_VERSION)
         valid = false;
      else
        {
         file_login = StringToInteger(header[2]);
         for(int i = 1; i < count; i++)
           {
            string fields[];
            if(StringSplit(lines[i], '|', fields) < 3)
               continue;
            if(fields[0] == "E")
              {
               g_ag_equity_anchor = (datetime)StringToInteger(fields[1]);
               g_ag_equity_peak   = StringToDouble(fields[2]);
              }
           }
        }
     }

   if(!valid)
      return AgEquityQuarantine(path, 2, "failed checksum or does not parse");
   if(file_login != g_ag_login)
      return AgEquityQuarantine(path, 3,
                                "carries login " + (string)file_login
                                + " but this account is " + (string)g_ag_login);
   return 0;
  }

//+------------------------------------------------------------------+
//| The equity term of the lock level: the day's running maximum of  |
//| pnl minus the POST RATCHET enforced_limit, never the raw live    |
//| limit. V2-D6 mandates the same post-ratchet value D7 mandates    |
//| for the realized term, so the three terms of the MathMax are     |
//| computed against one enforced limit and not three.               |
//|                                                                  |
//| The staleness rules are the realized peak's, deliberately and to |
//| the letter, because they answer the same three clock cases and   |
//| because D2 forbids either mechanism loosening what the other has |
//| tightened by any path. A peak belonging to an EARLIER day is     |
//| stale and contributes nothing, which is a leftover file no pass  |
//| has reconciled because the EA has not run a tick since the       |
//| rollover. A peak belonging to the SAME day applies, the ordinary |
//| case. A peak belonging to a LATER day also applies, which is     |
//| what a backward clock step produces, and holding it is RULED     |
//| rather than inherited: V2-D16 option (a) mirrors the peak block  |
//| here for the peak block's own reason, that a one-act disarm is   |
//| strictly worse than a laborious false trip.                      |
//|                                                                  |
//| A peak of zero contributes nothing, which is not a special case  |
//| but the arithmetic: peak - enforced_limit is then exactly        |
//| -enforced_limit, the ratchet term, and MathMax at the call site  |
//| sees a tie. Under V2-D15 option (b) the equity peak rises from   |
//| sampled pnl alone and is never pulled up by the realized term on |
//| an ordinary pass, so it may legitimately sit below the realized  |
//| peak; the three-term MathMax then takes the stricter term and    |
//| chosen=peak stays observable.                                    |
//+------------------------------------------------------------------+
double AgEquityEffectiveLevel(const double enforced_limit, const datetime window_anchor)
  {
   if(g_ag_equity_anchor < window_anchor || g_ag_equity_peak <= 0.0)
      return -enforced_limit;
   return g_ag_equity_peak - enforced_limit;
  }

//+------------------------------------------------------------------+
//| Single-instance mutex heartbeat (SPEC 5, F8).                    |
//| Live other instance: refuse. Stale mutex heartbeat: takeover.    |
//| Mutex heartbeat 0 = deliberate release by a clean OnDeinit.      |
//|                                                                  |
//| A frozen mutex heartbeat always reads stale, and staleness       |
//| authorizes takeover, so a refresh that silently stops disarms    |
//| single-instance protection completely. Every write is therefore  |
//| checked and logged rather than assumed.                          |
//+------------------------------------------------------------------+
bool AgMutexAcquire()
  {
   double hb = 0.0;
   if(GlobalVariableGet(AgGvHeartbeat(), hb) && hb > 0.5)
     {
      double age = (double)TimeLocal() - hb;   // A1 clock exemption
      if(age < AG_MUTEX_STALE_SECONDS)
         return false;                          // live instance holds it
      AgWarn("stale mutex heartbeat (" + DoubleToString(age, 0) + "s), taking over crashed-instance mutex");
     }
   g_ag_instance_id = (double)GetTickCount() * 65536.0 + (double)MathRand();

   string   id_name = AgGvInstance();
   string   hb_name = AgGvHeartbeat();
   datetime hb_now  = TimeLocal();             // A1 clock exemption

   bool id_set = GlobalVariableSet(id_name, g_ag_instance_id) > 0;
   bool hb_set = GlobalVariableSet(hb_name, (double)hb_now) > 0;
   GlobalVariablesFlush();

   AgInfo("mutex acquire|id_name=" + id_name + "|id_set=" + (id_set ? "1" : "0")
          + "|id_exists=" + (GlobalVariableCheck(id_name) ? "1" : "0")
          + "|hb_name=" + hb_name + "|hb_set=" + (hb_set ? "1" : "0")
          + "|hb_exists=" + (GlobalVariableCheck(hb_name) ? "1" : "0")
          + "|hb_value=" + (string)((long)hb_now));

   if(!id_set || !hb_set)
      AgAlertEvent("mutex write failed at acquire, single-instance protection is not in force"
                   + " (id_set=" + (id_set ? "1" : "0") + ", hb_set=" + (hb_set ? "1" : "0")
                   + ", error " + (string)GetLastError() + ")");
   return true;
  }

//+------------------------------------------------------------------+
//| Called from the first timer tick onward in EVERY state. Guardian |
//| liveness does not depend on history sync, breach evaluation, or  |
//| anything downstream, so nothing may gate this.                   |
//+------------------------------------------------------------------+
void AgMutexRefresh()
  {
   double id = 0.0;
   if(GlobalVariableGet(AgGvInstance(), id) && id != g_ag_instance_id)
     {
      AgAlertEvent("instance mutex overwritten by another instance, this should not happen");
      return;
     }
   datetime hb_now = TimeLocal();              // A1 clock exemption
   if(GlobalVariableSet(AgGvHeartbeat(), (double)hb_now) == 0)
      AgWarn("mutex heartbeat refresh failed, error " + (string)GetLastError()
             + ", takeover protection is degraded");
   GlobalVariablesFlush();
  }

void AgMutexRelease()
  {
   double id = 0.0;
   if(GlobalVariableGet(AgGvInstance(), id) && id == g_ag_instance_id)
     {
      GlobalVariableSet(AgGvHeartbeat(), 0.0);   // deliberate-release marker
      GlobalVariablesFlush();
     }
  }

#endif // AG_PERSIST_MQH
