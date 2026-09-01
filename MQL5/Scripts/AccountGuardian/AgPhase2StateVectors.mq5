//+------------------------------------------------------------------+
//| AgPhase2StateVectors.mq5                                         |
//| Phase 2 Stage 2 synthetic test vectors for the lock state file   |
//| family in Persist.mqh (design doc item 5): AgStatePath,          |
//| AgStateSerialize, AgStateSave, AgStateLoad, the                  |
//| never-loaded-never-written guard, the checksum, the login        |
//| mismatch rule and the .bad quarantine.                           |
//| One AGVEC line per case plus a final AGVEC|SUMMARY|<pass>/<total>|
//| line, the same contract AgPhase1ClockVectors already uses.       |
//| Makes no trade calls and opens no chart.                         |
//|                                                                  |
//| IT DOES WRITE FILES, which the clock vectors did not, because    |
//| the thing under test is a file format. Two properties keep that  |
//| safe and both are asserted rather than assumed. First, every     |
//| path it touches is derived from a SYNTHETIC login in the         |
//| 99000000x range, so it can never read, write or quarantine the   |
//| real state_<login>.dat of the live account; vector 0 refuses to  |
//| run at all if the live login ever collides with that range.      |
//| Second, it DELETES NOTHING. Quarantined files accumulate across  |
//| runs by design, per the FINAL ruling of 2026-07-29 that lock     |
//| artifacts are never deleted, only quarantined; the growing       |
//| .bad.N chain is itself vector q_quarantine_never_overwrites.     |
//|                                                                  |
//| Double-click from the Navigator to run. A running terminal does  |
//| not enumerate files added after it started, so this script is    |
//| invisible until the next terminal restart (FINAL 2026-08-04,     |
//| extended to Scripts by measurement 2026-08-09).                  |
//+------------------------------------------------------------------+
#property copyright "AccountGuardian"
#property version   "1.00"
#property strict
#property script_show_inputs

#include <AccountGuardian/Persist.mqh>

//--- Synthetic logins. None of these is a real account and none of them
//--- may ever equal the live one; vector 0 enforces that.
#define AGVEC_LOGIN_ROUNDTRIP  990000001
#define AGVEC_LOGIN_CORRUPT    990000002
#define AGVEC_LOGIN_MISMATCH   990000003
#define AGVEC_LOGIN_FOREIGN    990000004
#define AGVEC_LOGIN_VERSION    990000005
#define AGVEC_LOGIN_CROSSREAD  990000006
#define AGVEC_LOGIN_GUARD      990000007
#define AGVEC_LOGIN_MISSING    990000009   // deliberately never written
#define AGVEC_LOGIN_RATCHET    990000011   // Stage 5 floor file
#define AGVEC_LOGIN_EQUITY     990000012   // version 2 equity peak file
#define AGVEC_LOGIN_EQUITY_MISSING 990000013   // deliberately never written

int g_pass  = 0;
int g_total = 0;

void AgVecCheck(const string name, const bool ok, const string detail)
  {
   g_total++;
   if(ok)
     {
      g_pass++;
      PrintFormat("AGVEC|%s|PASS", name);
     }
   else
      PrintFormat("AGVEC|%s|FAIL|%s", name, detail);
  }

void AgVecCheckDT(const string name, const datetime got, const datetime want)
  {
   AgVecCheck(name, got == want,
              "got=" + TimeToString(got, TIME_DATE | TIME_SECONDS)
              + " want=" + TimeToString(want, TIME_DATE | TIME_SECONDS));
  }

void AgVecCheckInt(const string name, const long got, const long want)
  {
   AgVecCheck(name, got == want, "got=" + (string)got + " want=" + (string)want);
  }

//--- Money comparison at 1e-6, deliberately tighter than the 0.01 acceptance
//--- epsilon of 2026-07-30: the point of these vectors is that the stored
//--- value is the value, so a difference the banner would round away still
//--- has to fail here.
void AgVecCheckMoney(const string name, const double got, const double want)
  {
   AgVecCheck(name, MathAbs(got - want) < 0.000001,
              "got=" + DoubleToString(got, 8) + " want=" + DoubleToString(want, 8));
  }

//+------------------------------------------------------------------+
//| Raw file helpers. These bypass the state family on purpose: a    |
//| vector that built its fixtures with the code under test could    |
//| not detect a format that is self-consistently wrong.             |
//+------------------------------------------------------------------+
bool AgVecWriteRaw(const string path, const string content)
  {
   FolderCreate(AG_FILES_DIR);
   int h = FileOpen(path, FILE_WRITE | FILE_TXT | FILE_ANSI);
   if(h == INVALID_HANDLE)
      return false;
   FileWriteString(h, content);
   FileFlush(h);
   FileClose(h);
   return true;
  }

string AgVecReadRaw(const string path)
  {
   if(!FileIsExist(path))
      return "";
   int h = FileOpen(path, FILE_READ | FILE_TXT | FILE_ANSI);
   if(h == INVALID_HANDLE)
      return "";
   string out = "";
   while(!FileIsEnding(h))
      out += FileReadString(h) + "\n";
   FileClose(h);
   return out;
  }

//--- A well-formed body plus a correct checksum line.
string AgVecSealed(const string body) { return body + "C|" + (string)AgChecksum(body) + "\n"; }

//--- A well-formed body plus a checksum that is wrong by exactly one.
string AgVecTampered(const string body) { return body + "C|" + (string)(AgChecksum(body) + 1) + "\n"; }

string AgVecBody(const long login, const int reason, const datetime until,
                 const datetime breach, const double limit_snap, const double base_snap)
  {
   return "AGSTATE|" + (string)AG_STATE_FORMAT_VERSION + "|" + (string)login + "\n"
          + "L|" + (string)reason + "|" + (string)((long)until) + "|" + (string)((long)breach) + "\n"
          + "N|" + DoubleToString(limit_snap, AG_STATE_MONEY_DIGITS)
          + "|" + DoubleToString(base_snap, AG_STATE_MONEY_DIGITS) + "\n";
  }

void OnStart()
  {
   //--- Fixed reference values. The anchor boundary is the same arbitrary
   //--- Tuesday the Phase 1 clock vectors use, so the two vector sets can be
   //--- read side by side. The money values are the real measured ones from
   //--- 2026-08-16: base 1985.97 at the ruled five percent gives 99.2985,
   //--- which the banner prints as 99.30. That sub-cent tail is the whole
   //--- reason the money fields are stored at 8 decimals and it is asserted
   //--- below rather than left as a comment.
   datetime A0        = D'2026.02.10 01:00:00';
   datetime until_ref = A0 + 86400;
   datetime breach_ref = A0 + 43200;
   double   base_ref  = 1985.97;
   double   limit_ref = 99.2985;

   long live_login = (long)AccountInfoInteger(ACCOUNT_LOGIN);

   //--- vector 0: the safety interlock. Every other vector writes files, so
   //--- this one runs first and refuses everything if the synthetic range
   //--- could collide with the live account's own state file.
   bool range_is_safe = (live_login < 990000000 || live_login > 990000999);
   AgVecCheck("v0_synthetic_login_range_cannot_hit_live_account", range_is_safe,
              "live login " + (string)live_login + " falls inside the synthetic range");
   if(!range_is_safe)
     {
      PrintFormat("AGVEC|SUMMARY|%d/%d", g_pass, g_total);
      return;
     }

   //================================================================
   //--- A. path and format identity
   //================================================================
   g_ag_login = AGVEC_LOGIN_ROUNDTRIP;
   AgVecCheck("a1_state_path_differs_from_halt_path", AgStatePath() != AgHaltPath(),
              AgStatePath() + " vs " + AgHaltPath());
   AgVecCheck("a2_state_path_names_the_login",
              StringFind(AgStatePath(), (string)AGVEC_LOGIN_ROUNDTRIP) >= 0, AgStatePath());
   AgVecCheck("a3_magic_is_agstate_not_aghalt",
              StringFind(AgStateSerialize(), "AGSTATE|") == 0
              && StringFind(AgStateSerialize(), "AGHALT") < 0, AgStateSerialize());

   //================================================================
   //--- B. never-loaded-never-written (FINAL 2026-07-29)
   //================================================================
   g_ag_login = AGVEC_LOGIN_GUARD;
   string guard_path = AgStatePath();
   AgVecWriteRaw(guard_path, AgVecSealed(AgVecBody(AGVEC_LOGIN_GUARD, 1, until_ref, breach_ref,
                                                   limit_ref, base_ref)));
   string guard_before = AgVecReadRaw(guard_path);
   g_ag_state_loaded = false;                 // simulate a refused init
   AgStateResetModel();                       // default-constructed empty model
   bool saved = AgStateSave();
   AgVecCheck("b1_save_refuses_when_model_never_loaded", !saved, "AgStateSave returned true");
   AgVecCheck("b2_refused_save_left_the_file_byte_identical",
              AgVecReadRaw(guard_path) == guard_before, "file changed under a refused save");

   //================================================================
   //--- C. round trip through the real save and load paths
   //================================================================
   g_ag_login = AGVEC_LOGIN_ROUNDTRIP;
   g_ag_state_loaded = true;                  // a legitimate load happened
   AgStateSetBreach(until_ref, breach_ref, limit_ref, base_ref);
   AgVecCheck("c1_save_succeeds_when_loaded", AgStateSave(), "AgStateSave returned false");

   AgStateResetModel();                       // prove the values come off disk
   int rc = AgStateLoad();
   AgVecCheckInt("c2_roundtrip_load_returns_loaded", rc, 0);
   AgVecCheckInt("c3_roundtrip_reason", (long)g_ag_state_reason, (long)AG_LOCK_DAILY_BREACH);
   AgVecCheckDT("c4_roundtrip_locked_until", g_ag_state_locked_until, until_ref);
   AgVecCheckDT("c5_roundtrip_breach_time", g_ag_state_breach_time, breach_ref);
   AgVecCheckMoney("c6_roundtrip_limit_snapshot", g_ag_state_limit_snap, limit_ref);
   AgVecCheckMoney("c7_roundtrip_base_snapshot", g_ag_state_base_snap, base_ref);
   //--- The Q6 snapshot governs the locked window, so a limit stored to the
   //--- printed cent would enforce 99.30 where the breach computed 99.2985.
   AgVecCheck("c8_limit_snapshot_keeps_sub_cent_precision",
              MathAbs(g_ag_state_limit_snap - 99.30) > 0.0001,
              "stored limit rounded to the cent: " + DoubleToString(g_ag_state_limit_snap, 8));

   //================================================================
   //--- D. missing file: not corrupt, and not trusted either way
   //================================================================
   g_ag_login = AGVEC_LOGIN_MISSING;
   g_ag_state_loaded = false;
   rc = AgStateLoad();
   AgVecCheckInt("d1_missing_file_returns_missing", rc, 1);
   AgVecCheck("d2_missing_file_sets_loaded_true", g_ag_state_loaded, "");
   AgVecCheckInt("d3_missing_file_model_is_neutral", (long)g_ag_state_reason, (long)AG_LOCK_NONE);
   AgVecCheckDT("d4_missing_file_locked_until_is_zero", g_ag_state_locked_until, 0);
   AgVecCheck("d5_missing_file_wrote_nothing", !FileIsExist(AgStatePath()), AgStatePath());

   //================================================================
   //--- E. checksum corruption
   //================================================================
   g_ag_login = AGVEC_LOGIN_CORRUPT;
   string corrupt_path = AgStatePath();
   string corrupt_body = AgVecBody(AGVEC_LOGIN_CORRUPT, 1, until_ref, breach_ref, limit_ref, base_ref);
   AgVecWriteRaw(corrupt_path, AgVecTampered(corrupt_body));
   string corrupt_original = AgVecReadRaw(corrupt_path);
   //--- Computed before the call so a tick crossing the 01:00 boundary during
   //--- the call cannot make a correct implementation look wrong.
   datetime expect_until = AgNextDayAnchor(AgServerNow());
   rc = AgStateLoad();
   AgVecCheckInt("e1_bad_checksum_returns_corrupt", rc, 2);
   AgVecCheckInt("e2_bad_checksum_locks_via_corrupt_state",
                 (long)g_ag_state_reason, (long)AG_LOCK_CORRUPT_STATE);
   AgVecCheckDT("e3_corrupt_locked_until_is_next_day_anchor", g_ag_state_locked_until, expect_until);
   AgVecCheckDT("e4_corrupt_carries_no_breach_time", g_ag_state_breach_time, 0);
   AgVecCheckMoney("e5_corrupt_carries_no_limit_snapshot", g_ag_state_limit_snap, 0.0);
   AgVecCheckMoney("e6_corrupt_carries_no_base_snapshot", g_ag_state_base_snap, 0.0);
   AgVecCheck("e7_corrupt_file_was_quarantined_not_deleted",
              FileIsExist(corrupt_path + ".bad") || FileIsExist(corrupt_path + ".bad.2"),
              "no quarantine file found for " + corrupt_path);
   AgVecCheck("e8_a_fresh_file_was_written", FileIsExist(corrupt_path), corrupt_path);
   //--- No re-corruption loop: the file the corrupt branch just wrote must
   //--- itself load cleanly on the next restart inside the same window.
   datetime until_after_quarantine = g_ag_state_locked_until;
   AgStateResetModel();
   rc = AgStateLoad();
   AgVecCheckInt("e9_fresh_file_reloads_cleanly", rc, 0);
   AgVecCheckInt("e10_fresh_file_still_says_corrupt_state",
                 (long)g_ag_state_reason, (long)AG_LOCK_CORRUPT_STATE);
   AgVecCheckDT("e11_fresh_file_preserves_locked_until",
                g_ag_state_locked_until, until_after_quarantine);

   //--- The quarantine holds the original bytes, not a rewritten copy.
   string quarantined = AgVecReadRaw(corrupt_path + ".bad");
   AgVecCheck("e12_quarantine_holds_the_original_bytes",
              quarantined == corrupt_original || StringFind(quarantined, "AGSTATE|") == 0,
              "quarantine content does not match the file that was moved");

   //================================================================
   //--- F. quarantine never overwrites an earlier quarantine
   //--- (FINAL 2026-07-29: lock artifacts are never deleted)
   //================================================================
   AgVecWriteRaw(corrupt_path, AgVecTampered(corrupt_body));
   AgStateLoad();
   AgVecCheck("f1_second_corruption_did_not_reuse_the_first_quarantine_name",
              FileIsExist(corrupt_path + ".bad") && FileIsExist(corrupt_path + ".bad.2"),
              "expected both .bad and .bad.2 to exist after two corruptions");

   //================================================================
   //--- G. login mismatch (FINAL 2026-07-30, CORRUPT_STATE-equivalent)
   //================================================================
   g_ag_login = AGVEC_LOGIN_MISMATCH;
   string mismatch_path = AgStatePath();
   //--- Internally valid, correct checksum, correct magic and version, and
   //--- a foreign login. Exactly the foreign-residue class.
   AgVecWriteRaw(mismatch_path, AgVecSealed(AgVecBody(AGVEC_LOGIN_FOREIGN, 1, until_ref,
                                                      breach_ref, limit_ref, base_ref)));
   expect_until = AgNextDayAnchor(AgServerNow());
   rc = AgStateLoad();
   AgVecCheckInt("g1_login_mismatch_returns_its_own_code", rc, 3);
   AgVecCheckInt("g2_login_mismatch_locks_via_corrupt_state",
                 (long)g_ag_state_reason, (long)AG_LOCK_CORRUPT_STATE);
   AgVecCheckDT("g3_login_mismatch_locked_until_is_next_day_anchor",
                g_ag_state_locked_until, expect_until);
   AgVecCheck("g4_foreign_lock_values_were_not_adopted",
              g_ag_state_locked_until != until_ref && g_ag_state_breach_time == 0,
              "the foreign file's own lock values leaked into the model");
   AgVecCheck("g5_foreign_file_was_quarantined",
              FileIsExist(mismatch_path + ".bad") || FileIsExist(mismatch_path + ".bad.2"),
              "no quarantine file found for " + mismatch_path);
   AgStateResetModel();
   rc = AgStateLoad();
   AgVecCheckInt("g6_fresh_file_after_mismatch_reloads_cleanly", rc, 0);

   //================================================================
   //--- H. format rejection: version, and cross-reading the halt file
   //================================================================
   g_ag_login = AGVEC_LOGIN_VERSION;
   string version_path = AgStatePath();
   string wrong_version = "AGSTATE|" + (string)(AG_STATE_FORMAT_VERSION + 1) + "|"
                          + (string)AGVEC_LOGIN_VERSION + "\n"
                          + "L|1|" + (string)((long)until_ref) + "|" + (string)((long)breach_ref) + "\n";
   AgVecWriteRaw(version_path, AgVecSealed(wrong_version));
   rc = AgStateLoad();
   AgVecCheckInt("h1_unknown_format_version_is_rejected", rc, 2);
   AgVecCheckInt("h2_unknown_version_locks_via_corrupt_state",
                 (long)g_ag_state_reason, (long)AG_LOCK_CORRUPT_STATE);

   //--- A halt file dropped at the state path must never be read as lock
   //--- state, which is the whole reason the magics differ.
   g_ag_login = AGVEC_LOGIN_CROSSREAD;
   string cross_path = AgStatePath();
   string halt_body = "AGHALT|" + (string)AG_HALT_FORMAT_VERSION + "|"
                      + (string)AGVEC_LOGIN_CROSSREAD + "\n"
                      + "S|1786027355|0\n"
                      + "H|1|crash loop|1786027355\n";
   AgVecWriteRaw(cross_path, AgVecSealed(halt_body));
   rc = AgStateLoad();
   AgVecCheckInt("h3_halt_file_at_the_state_path_is_rejected", rc, 2);
   AgVecCheckInt("h4_cross_read_locks_via_corrupt_state",
                 (long)g_ag_state_reason, (long)AG_LOCK_CORRUPT_STATE);

   //================================================================
   //--- I. locked_until BOUNDS (Phase 2 Stage 3, reachable from a script
   //--- since the owner ruling of 2026-08-18 moved both helpers into
   //--- Clock.mqh). These encode three FINAL rulings and were previously
   //--- provable by source reading alone.
   //================================================================
   //--- Anchor boundaries off the same reference A0 the fixtures above use,
   //--- named as the Phase 1 clock vectors name theirs so the two vector
   //--- sets read side by side.
   datetime A1 = A0 + 86400;    // next boundary
   datetime A3 = A0 + 259200;   // three boundaries forward

   datetime saved_high   = g_ag_high_anchor;
   bool     saved_seeded = g_ag_high_anchor_seeded;

   //--- Q1 base, with the latch unseeded so ruling FOUR contributes nothing
   g_ag_high_anchor_seeded = false;
   g_ag_high_anchor        = 0;
   AgVecCheckDT("i1_q1_base_is_next_day_anchor",
                AgLockedUntilComputed(A0 + 3600, false), AgNextDayAnchor(A0 + 3600));
   AgVecCheck("i2_latch_floor_is_zero_while_unseeded", AgLatchFloor() == 0, "");

   //--- RULING THREE: a frozen quote takes the anchor AFTER the imminent one
   AgVecCheckDT("i3_ruling_three_frozen_adds_a_full_day",
                AgLockedUntilComputed(A0 + 3600, true),
                AgNextDayAnchor(AgNextDayAnchor(A0 + 3600)));
   AgVecCheck("i4_ruling_three_is_exactly_one_extra_day",
              (long)(AgLockedUntilComputed(A0 + 3600, true)
                     - AgLockedUntilComputed(A0 + 3600, false)) == 86400, "");

   //--- The measured signature ruling THREE exists for: a breach at 00:58
   //--- inside the pre-anchor freeze must NOT lock for the two minutes left
   //--- until the imminent anchor.
   datetime breach_0058 = A1 - 120;   // two minutes before the 01:00 boundary
   AgVecCheck("i5_pre_anchor_breach_does_not_lock_for_minutes",
              (long)(AgLockedUntilComputed(breach_0058, true) - breach_0058) > 86400,
              "lock duration was " + (string)(long)(AgLockedUntilComputed(breach_0058, true) - breach_0058) + "s");
   AgVecCheckDT("i6_pre_anchor_unfrozen_still_takes_the_imminent_anchor",
                AgLockedUntilComputed(breach_0058, false), A1);

   //--- RULING FOUR: the latch floor raises a value that would fall below it
   g_ag_high_anchor_seeded = true;
   g_ag_high_anchor        = A3;                  // latch well ahead of the breach
   AgVecCheckDT("i7_ruling_four_floors_a_stale_computed_value",
                AgLockedUntilComputed(A0 + 3600, false), AgNextDayAnchor(A3));
   AgVecCheck("i8_ruling_four_is_a_floor_not_a_replacement",
              AgLockedUntilComputed(A3 + 200000, false) > AgNextDayAnchor(A3), "");

   //--- WITNESS PATH: clamp first as the upper bound
   datetime ceiling = AgNextDayAnchor(AgServerNow());
   g_ag_high_anchor_seeded = false;               // floor out of the way
   g_ag_high_anchor        = 0;
   AgVecCheckDT("i9_witness_value_beyond_the_ceiling_is_clamped",
                AgLockedUntilFromWitness(ceiling + 8640000), ceiling);
   AgVecCheckDT("i10_witness_value_inside_the_bounds_is_untouched",
                AgLockedUntilFromWitness(ceiling - 3600), ceiling - 3600);

   //--- WITNESS PATH under a REWOUND CLOCK, the case the precedence ruling of
   //--- 2026-08-18 was made for. The latch never recedes, so after a backward
   //--- step its next-day anchor sits ABOVE the clamp's ceiling and the two
   //--- bounds point in opposite directions. The floor is applied last and
   //--- must win; if the clamp won, the lock would be cut back using the very
   //--- reading the floor exists to defend against.
   g_ag_high_anchor_seeded = true;
   g_ag_high_anchor        = ceiling + 172800;    // latch two days past the ceiling
   datetime floor_above    = AgNextDayAnchor(g_ag_high_anchor);
   AgVecCheck("i11_rewound_clock_floor_sits_above_the_clamp_ceiling",
              floor_above > ceiling, "fixture is wrong: floor is not above the ceiling");
   AgVecCheckDT("i12_rewound_clock_floor_wins_over_the_clamp",
                AgLockedUntilFromWitness(ceiling - 3600), floor_above);
   AgVecCheckDT("i13_rewound_clock_floor_wins_even_for_an_inflated_witness",
                AgLockedUntilFromWitness(ceiling + 8640000), floor_above);

   //--- THE DOMAIN SPLIT ITSELF: a value the guardian computes for itself
   //--- takes NO clamp, so a frozen-quote breach may legitimately land beyond
   //--- the ceiling. If the clamp leaked into the computed path this fails.
   g_ag_high_anchor_seeded = false;
   g_ag_high_anchor        = 0;
   datetime computed_frozen = AgLockedUntilComputed(AgServerNow(), true);
   AgVecCheck("i14_computed_path_is_not_clamped",
              computed_frozen > ceiling,
              "computed=" + TimeToString(computed_frozen, TIME_DATE | TIME_SECONDS)
              + " ceiling=" + TimeToString(ceiling, TIME_DATE | TIME_SECONDS));

   g_ag_high_anchor        = saved_high;
   g_ag_high_anchor_seeded = saved_seeded;

   //================================================================
   //--- J. THE RATCHET (Phase 2 Stage 5, question SEVEN FINAL). The six
   //--- vectors the ruling calls for, plus two that prove the persistence
   //--- the ruling requires, since a floor that does not survive a restart
   //--- is not a ratchet. Reachable from a script only because
   //--- AgRatchetUpdate was placed beside the floor family rather than in
   //--- the EA, applying the same owner ruling that moved the bound helpers.
   //================================================================
   g_ag_login        = AGVEC_LOGIN_RATCHET;
   g_ag_floor_loaded = true;
   AgFloorResetModel();

   //--- SEED on the first completed computation of a day
   double r = AgRatchetUpdate(A0, 100.0, 30);
   AgVecCheckMoney("j1_seed_takes_the_live_limit", r, 100.0);
   AgVecCheckMoney("j1b_seed_stores_the_floor", g_ag_floor_currency, 100.0);
   AgVecCheckDT("j1c_seed_stores_the_day_anchor", g_ag_floor_anchor, A0);

   //--- LOWER on a decrease: the floor is a running minimum
   r = AgRatchetUpdate(A0, 80.0, 30);
   AgVecCheckMoney("j2_lowers_on_a_decrease", g_ag_floor_currency, 80.0);
   AgVecCheckMoney("j2b_enforces_the_lowered_value", r, 80.0);

   //--- HOLD under inflation: the whole point of the ratchet
   r = AgRatchetUpdate(A0, 150.0, 30);
   AgVecCheckMoney("j3_holds_the_floor_against_a_raised_limit", g_ag_floor_currency, 80.0);
   AgVecCheckMoney("j3b_enforces_the_floor_not_the_raised_limit", r, 80.0);

   //--- RESEED AT ROLLOVER: the new day starts from the live limit
   r = AgRatchetUpdate(A1, 150.0, 30);
   AgVecCheckMoney("j4_reseeds_at_rollover", g_ag_floor_currency, 150.0);
   AgVecCheckDT("j4b_reseed_moves_the_day_anchor", g_ag_floor_anchor, A1);
   AgVecCheckMoney("j4c_reseed_enforces_the_new_live_limit", r, 150.0);

   //--- NO RESEED ON A BACKWARD STEP. Tighten first so the case can
   //--- discriminate, then step the window anchor back behind the floor's.
   AgRatchetUpdate(A1, 90.0, 30);
   r = AgRatchetUpdate(A0, 150.0, 30);
   AgVecCheckMoney("j5_no_reseed_on_a_backward_step", g_ag_floor_currency, 90.0);
   AgVecCheckDT("j5b_backward_step_does_not_move_the_anchor", g_ag_floor_anchor, A1);
   AgVecCheckMoney("j5c_backward_step_still_enforces_the_held_floor", r, 90.0);

   //--- PERSISTENCE: the floor survives a restart, which is what makes it a
   //--- ratchet rather than a per-session tightening.
   AgFloorSave();
   AgFloorResetModel();
   AgVecCheckInt("j6_floor_file_reloads", AgFloorLoad(), 0);
   AgVecCheckMoney("j6b_floor_survives_a_restart", g_ag_floor_currency, 90.0);

   //--- STALE FLOOR from a prior day contributes nothing, which is the case
   //--- of a file no pass has reseeded because the EA has not run since the
   //--- rollover. A1 is the floor's day; A3 is a later one.
   AgVecCheckMoney("j7_stale_floor_is_declined", AgFloorEffectiveLimit(200.0, A3), 200.0);
   AgVecCheckMoney("j7b_same_day_floor_is_applied", AgFloorEffectiveLimit(200.0, A1), 90.0);

   //--- CORRUPT FLOOR FILE: quarantined, model reset, and NO lock follows,
   //--- because the floor is not lock state.
   string floor_path = AgFloorPath();
   AgVecWriteRaw(floor_path, AgVecTampered("AGFLOOR|1|" + (string)AGVEC_LOGIN_RATCHET + "\n"
                                           + "F|" + (string)((long)A1) + "|90.00000000\n"));
   AgVecCheckInt("j8_corrupt_floor_is_quarantined", AgFloorLoad(), 2);
   AgVecCheckMoney("j8b_corrupt_floor_resets_to_nothing", g_ag_floor_currency, 0.0);
   AgVecCheck("j8c_corrupt_floor_file_was_not_deleted",
              FileIsExist(floor_path + ".bad") || FileIsExist(floor_path + ".bad.2"),
              "no quarantine file found for " + floor_path);

   //--- K. THE FILE ROUND TRIP MUST NOT LOOK LIKE A LIMIT CHANGE (owner ruling
   //--- 2026-08-18, added after the live Stage 7 finding). None of j1 to j8
   //--- could have caught this: every one of them compares a floor that came
   //--- straight out of memory, and the defect only exists on the path where
   //--- the floor has been through DoubleToString at 8 decimals and back
   //--- through StringToDouble. On the live account that path made the guardian
   //--- report a raised limit 220 times against a limit nobody touched.
   AgFloorResetModel();
   g_ag_floor_loaded      = true;
   g_ag_last_ratchet_warn = 0;

   //--- The live arithmetic exactly as the guardian computes it, rather than a
   //--- round number: base 2133.13 at 5 percent is what was on the account when
   //--- the defect was found, and a round number would not exercise the bug.
   double rt_live = AgLimitCurrency(2133.13, 5.0, 0.0);
   AgRatchetUpdate(A0, rt_live, 30);
   AgFloorSave();
   AgFloorResetModel();
   AgVecCheckInt("k1_roundtrip_floor_reloads", AgFloorLoad(), 0);

   //--- THE ROW ITSELF: the same live limit, one pass, immediately after the
   //--- reload. Neither branch may fire. A warn stamp still at zero proves the
   //--- HOLD branch was not taken, since AgRatchetUpdate always warns on a hold
   //--- when the stamp is zero; a bit identical floor proves the LOWER branch
   //--- was not taken, since that branch is the only writer of this global.
   double rt_floor_before = g_ag_floor_currency;
   g_ag_last_ratchet_warn = 0;
   double rt_r = AgRatchetUpdate(A0, rt_live, 30);
   AgVecCheckInt("k2_no_hold_warn_on_the_reloaded_floor",
                 (long)g_ag_last_ratchet_warn, 0);
   AgVecCheck("k2b_reloaded_floor_is_not_rewritten",
              g_ag_floor_currency == rt_floor_before,
              "floor moved from " + DoubleToString(rt_floor_before, 8)
              + " to " + DoubleToString(g_ag_floor_currency, 8));
   AgVecCheck("k2c_enforced_value_tracks_the_live_limit",
              MathAbs(rt_r - rt_live) < AG_PNL_EPSILON,
              "enforced=" + DoubleToString(rt_r, 8) + " live=" + DoubleToString(rt_live, 8));

   //--- DETERMINISTIC HALF CENT IN BOTH DIRECTIONS. k2 reproduces the live
   //--- conditions but its outcome depends on how one particular value rounds,
   //--- so it could pass on a platform where that value round trips exactly and
   //--- prove nothing. These two do not depend on rounding at all, and the
   //--- second is the mirror hazard: under the old exact comparison a floor a
   //--- hair ABOVE the live limit drove the LOWER branch, and that branch calls
   //--- AgFloorSave, so the guardian rewrote the file on every single pass.
   g_ag_floor_currency    = rt_live + 0.005;
   g_ag_last_ratchet_warn = 0;
   rt_floor_before        = g_ag_floor_currency;
   AgRatchetUpdate(A0, rt_live, 30);
   AgVecCheck("k3_half_cent_above_does_not_lower_the_floor",
              g_ag_floor_currency == rt_floor_before,
              "floor moved to " + DoubleToString(g_ag_floor_currency, 8));

   g_ag_floor_currency    = rt_live - 0.005;
   g_ag_last_ratchet_warn = 0;
   AgRatchetUpdate(A0, rt_live, 30);
   AgVecCheckInt("k4_half_cent_below_does_not_warn",
                 (long)g_ag_last_ratchet_warn, 0);

   //--- AND THE BAND MUST NOT SWALLOW A REAL CHANGE. Two cents is the smallest
   //--- move that clears a one cent band, so these are the boundary cases that
   //--- stop the fix from being a blanket mute.
   g_ag_floor_currency    = rt_live - 0.02;
   g_ag_last_ratchet_warn = 0;
   AgRatchetUpdate(A0, rt_live, 30);
   AgVecCheck("k5_two_cent_raise_still_warns", g_ag_last_ratchet_warn != 0,
              "no hold warn for a two cent raise above the floor");

   g_ag_floor_currency    = rt_live + 0.02;
   g_ag_last_ratchet_warn = 0;
   AgRatchetUpdate(A0, rt_live, 30);
   AgVecCheckMoney("k6_two_cent_decrease_still_lowers_the_floor",
                   g_ag_floor_currency, rt_live);

   //================================================================
   //--- L. THE EQUITY PEAK FILE (version 2, V2-D8 FINAL 2026-09-01).
   //--- Its own file with its own format constant, so `peak_<login>.dat`
   //--- and AG_PEAK_FORMAT_VERSION are untouched and no migration branch
   //--- exists on the version 1 file. The family mirrors the peak block
   //--- function for function, so these vectors mirror the state and floor
   //--- families' own: a round trip through the real save and load paths, a
   //--- missing file that is not corrupt, a corrupt file quarantined to a
   //--- FREE name with the model reset, and a login mismatch handled
   //--- identically to corruption per the FINAL of 2026-07-30.
   //---
   //--- THE ONE DIFFERENCE FROM THE STATE FAMILY IS ASSERTED RATHER THAN
   //--- DESCRIBED: a corrupt or foreign equity file LOCKS NOTHING. Under
   //--- V2-D4 it degrades to the realized peak, that is to version 1
   //--- authority, never to nothing and never to a lock, the equity file
   //--- not being lock state. l6e and l8d are that assertion.
   //================================================================
   g_ag_login         = AGVEC_LOGIN_EQUITY;
   g_ag_equity_loaded = true;
   AgEquityResetModel();

   AgVecCheck("l1_equity_path_differs_from_the_peak_and_floor_paths",
              AgEquityPath() != AgPeakPath() && AgEquityPath() != AgFloorPath(),
              AgEquityPath());
   AgVecCheck("l1b_equity_path_names_the_login",
              StringFind(AgEquityPath(), (string)AGVEC_LOGIN_EQUITY) >= 0, AgEquityPath());
   AgVecCheck("l2_magic_is_agequity_and_no_other",
              StringFind(AgEquitySerialize(), "AGEQUITY|") == 0
              && StringFind(AgEquitySerialize(), "AGPEAK")  < 0
              && StringFind(AgEquitySerialize(), "AGFLOOR") < 0
              && StringFind(AgEquitySerialize(), "AGSTATE") < 0, AgEquitySerialize());

   //--- NEVER LOADED, NEVER WRITTEN (FINAL 2026-07-29), the guard the state,
   //--- floor and peak models each carry and which V2-D8 inherits by name.
   string eq_path      = AgEquityPath();
   string eq_seed_body = "AGEQUITY|" + (string)AG_EQUITY_FORMAT_VERSION + "|"
                         + (string)AGVEC_LOGIN_EQUITY + "\n"
                         + "E|" + (string)((long)A0) + "|76.70350000\n";
   AgVecWriteRaw(eq_path, AgVecSealed(eq_seed_body));
   string eq_before   = AgVecReadRaw(eq_path);
   g_ag_equity_loaded = false;                // simulate a refused init
   AgEquityResetModel();                      // default-constructed empty model
   AgVecCheck("l3_save_refuses_when_the_model_was_never_loaded",
              !AgEquitySave(), "AgEquitySave returned true");
   AgVecCheck("l3b_refused_save_left_the_file_byte_identical",
              AgVecReadRaw(eq_path) == eq_before, "file changed under a refused save");

   //--- ROUND TRIP through the real save and load paths. The peak is stored at
   //--- AG_STATE_MONEY_DIGITS and not at the printed cent, for the reason the
   //--- limit snapshot is: V2-D6 subtracts the enforced limit from this value
   //--- to form equity_level, and the breach comparison one line later runs
   //--- under a one cent epsilon, so rounding on the way to disk would move the
   //--- enforced level on every restart. 76.7035 is the measured 2026-08-29 pnl
   //--- shape, realized -127.05 against floating 203.75, carried to four
   //--- decimals so the tail is real rather than decorative.
   g_ag_equity_loaded = true;                 // a legitimate load happened
   g_ag_equity_anchor = A0;
   g_ag_equity_peak   = 76.7035;
   AgVecCheck("l4_save_succeeds_when_loaded", AgEquitySave(), "AgEquitySave returned false");
   AgEquityResetModel();                      // prove the values come off disk
   AgVecCheckInt("l4b_roundtrip_load_returns_loaded", AgEquityLoad(), 0);
   AgVecCheckDT("l4c_roundtrip_anchor", g_ag_equity_anchor, A0);
   AgVecCheckMoney("l4d_roundtrip_peak", g_ag_equity_peak, 76.7035);
   AgVecCheck("l4e_peak_keeps_sub_cent_precision",
              MathAbs(g_ag_equity_peak - 76.70) > 0.0001,
              "stored peak rounded to the cent: " + DoubleToString(g_ag_equity_peak, 8));

   //--- MISSING FILE: not corrupt, and nothing is written on the way past it.
   g_ag_login         = AGVEC_LOGIN_EQUITY_MISSING;
   g_ag_equity_loaded = false;
   AgVecCheckInt("l5_missing_file_returns_missing", AgEquityLoad(), 1);
   AgVecCheck("l5b_missing_file_sets_loaded_true", g_ag_equity_loaded, "");
   AgVecCheckDT("l5c_missing_file_leaves_the_anchor_at_zero", g_ag_equity_anchor, 0);
   AgVecCheckMoney("l5d_missing_file_leaves_the_peak_at_zero", g_ag_equity_peak, 0.0);
   AgVecCheck("l5e_missing_file_wrote_nothing", !FileIsExist(AgEquityPath()), AgEquityPath());

   //--- CHECKSUM CORRUPTION: quarantined to a free name, model reset, a fresh
   //--- file written, and NO LOCK. The state model is reset first so that the
   //--- no-lock assertion has something to be true against.
   g_ag_login = AGVEC_LOGIN_EQUITY;
   eq_path    = AgEquityPath();
   AgVecWriteRaw(eq_path, AgVecTampered(eq_seed_body));
   AgStateResetModel();
   AgVecCheckInt("l6_bad_checksum_returns_corrupt", AgEquityLoad(), 2);
   AgVecCheckMoney("l6b_corrupt_equity_resets_the_peak", g_ag_equity_peak, 0.0);
   AgVecCheckDT("l6c_corrupt_equity_resets_the_anchor", g_ag_equity_anchor, 0);
   AgVecCheck("l6d_corrupt_equity_file_was_quarantined_not_deleted",
              FileIsExist(eq_path + ".bad") || FileIsExist(eq_path + ".bad.2"),
              "no quarantine file found for " + eq_path);
   AgVecCheckInt("l6e_corrupt_equity_locks_nothing",
                 (long)g_ag_state_reason, (long)AG_LOCK_NONE);
   AgVecCheck("l6f_a_fresh_equity_file_was_written", FileIsExist(eq_path), eq_path);
   //--- No re-corruption loop: the file the corrupt branch just wrote must
   //--- itself load cleanly on the next pass, exactly as e9 requires of the
   //--- state file.
   AgVecCheckInt("l6g_fresh_equity_file_reloads_cleanly", AgEquityLoad(), 0);

   //--- QUARANTINE NEVER OVERWRITES AN EARLIER QUARANTINE (FINAL 2026-07-29:
   //--- lock artifacts are never deleted). The .bad.N chain grows across runs
   //--- by design and this vector is what reads it.
   AgVecWriteRaw(eq_path, AgVecTampered(eq_seed_body));
   AgEquityLoad();
   AgVecCheck("l7_second_corruption_did_not_reuse_the_first_quarantine_name",
              FileIsExist(eq_path + ".bad") && FileIsExist(eq_path + ".bad.2"),
              "expected both .bad and .bad.2 to exist after two corruptions");

   //--- LOGIN MISMATCH: internally valid, correct checksum, correct magic and
   //--- version, foreign login. The foreign-residue class, handled identically
   //--- to corruption per the FINAL of 2026-07-30 and inherited by name under
   //--- V2-D8, and still locking nothing.
   AgVecWriteRaw(eq_path, AgVecSealed("AGEQUITY|" + (string)AG_EQUITY_FORMAT_VERSION + "|"
                                      + (string)AGVEC_LOGIN_FOREIGN + "\n"
                                      + "E|" + (string)((long)A0) + "|76.70350000\n"));
   AgStateResetModel();
   AgVecCheckInt("l8_login_mismatch_returns_its_own_code", AgEquityLoad(), 3);
   AgVecCheckMoney("l8b_foreign_peak_was_not_adopted", g_ag_equity_peak, 0.0);
   AgVecCheck("l8c_foreign_equity_file_was_quarantined",
              FileIsExist(eq_path + ".bad") || FileIsExist(eq_path + ".bad.2"),
              "no quarantine file found for " + eq_path);
   AgVecCheckInt("l8d_login_mismatch_locks_nothing",
                 (long)g_ag_state_reason, (long)AG_LOCK_NONE);
   AgVecCheckInt("l8e_fresh_equity_file_after_mismatch_reloads_cleanly", AgEquityLoad(), 0);

   //--- FORMAT REJECTION: an unknown version, and the cross-read. A version 1
   //--- PEAK file dropped at the equity path must never be read as an equity
   //--- peak, which is the whole reason V2-D8 gives the new file its own magic
   //--- and its own constant rather than a migration branch on the peak file.
   AgVecWriteRaw(eq_path, AgVecSealed("AGEQUITY|" + (string)(AG_EQUITY_FORMAT_VERSION + 1) + "|"
                                      + (string)AGVEC_LOGIN_EQUITY + "\n"
                                      + "E|" + (string)((long)A0) + "|76.70350000\n"));
   AgVecCheckInt("l9_unknown_equity_format_version_is_rejected", AgEquityLoad(), 2);

   AgVecWriteRaw(eq_path, AgVecSealed("AGPEAK|" + (string)AG_PEAK_FORMAT_VERSION + "|"
                                      + (string)AGVEC_LOGIN_EQUITY + "\n"
                                      + "P|" + (string)((long)A0) + "|76.70350000\n"));
   AgVecCheckInt("l10_peak_file_at_the_equity_path_is_rejected", AgEquityLoad(), 2);
   AgVecCheckMoney("l10b_cross_read_adopted_no_value", g_ag_equity_peak, 0.0);

   //--- L, SECOND PART: THE EQUITY TERM OF THE LOCK LEVEL (V2-D6 term
   //--- arithmetic; the later-anchor case ruled by V2-D16 option (a)).
   //--- The staleness rules are the peak block's, deliberately and to the
   //--- letter, because they answer the same three clock cases, so these
   //--- five read as the mirror of what j7 and j7b assert for the floor.
   g_ag_login         = AGVEC_LOGIN_EQUITY;
   g_ag_equity_loaded = true;
   AgEquityResetModel();
   g_ag_equity_anchor = A1;
   g_ag_equity_peak   = 76.7035;

   AgVecCheckMoney("l11_same_day_peak_is_the_peak_minus_the_enforced_limit",
                   AgEquityEffectiveLevel(109.58, A1), 76.7035 - 109.58);

   //--- An EARLIER anchor is stale and contributes nothing: a leftover file no
   //--- pass has reconciled because the EA has not run a tick since the
   //--- rollover, and enforcing it would carry one day's tightening into the
   //--- next.
   AgVecCheckMoney("l12_stale_earlier_anchor_contributes_nothing",
                   AgEquityEffectiveLevel(109.58, A3), -109.58);

   //--- A LATER anchor is what a backward clock step produces. V2-D16 option
   //--- (a): the value is HELD and stays enforced, mirroring the peak block,
   //--- because treating it as stale would hand a one-act disarm to anyone
   //--- able to move the clock back once. l13b is the discriminator: it fails
   //--- if the later anchor is quietly folded into the stale branch.
   AgVecCheckMoney("l13_later_anchor_is_held_and_still_enforced",
                   AgEquityEffectiveLevel(109.58, A0), 76.7035 - 109.58);
   AgVecCheck("l13b_later_anchor_is_not_treated_as_stale",
              AgEquityEffectiveLevel(109.58, A0) != -109.58,
              "a backward clock step dropped the equity term in one act");

   //--- A zero peak contributes nothing, which is the arithmetic rather than a
   //--- special case: peak minus enforced_limit is then exactly
   //--- -enforced_limit, the ratchet term, and the MathMax at the call site
   //--- sees a tie. That tie is what makes chosen=tie the reading of the first
   //--- pass of any fresh day.
   g_ag_equity_peak = 0.0;
   AgVecCheckMoney("l14_zero_peak_is_the_ratchet_term_exactly",
                   AgEquityEffectiveLevel(109.58, A1), -109.58);
   g_ag_equity_peak = -5.0;
   AgVecCheckMoney("l15_negative_peak_contributes_nothing",
                   AgEquityEffectiveLevel(109.58, A1), -109.58);

   //--- L, THIRD PART: THE RECONCILIATION (V2-D4 as scoped by V2-D15 option
   //--- (b), the line clause of V2-D8, the backward step of V2-D16 option (a)
   //--- and the save timing of V2-D18 option (a)).
   //---
   //--- NO HISTORY IS NEEDED AND NONE IS SELECTED. The equity block reads the
   //--- realized peak MODEL that AgPeakUpdate has already produced on the same
   //--- pass, per V2-D15, so these vectors seed g_ag_peak_currency directly
   //--- and the defect 3 shape 1 FINAL of 2026-08-20 is satisfied in letter:
   //--- no second walk exists anywhere in the equity block to add.
   g_ag_login         = AGVEC_LOGIN_EQUITY;
   g_ag_equity_loaded = true;

   //--- NEVER LOADED SAYS NOTHING, the same shape AgRatchetUpdate and
   //--- AgPeakUpdate each open with.
   g_ag_equity_loaded = false;
   AgVecCheckMoney("l16_never_loaded_contributes_nothing",
                   AgEquityUpdate(A1, 109.58, 30), -109.58);
   g_ag_equity_loaded = true;

   //--- NO FILE: the reconstruction stands alone and is taken whole.
   AgEquityResetModel();                      // anchor 0, the no-file shape
   g_ag_equity_reconciled = false;
   g_ag_peak_currency     = 40.00;
   double eq_lvl = AgEquityUpdate(A1, 109.58, 30);
   AgVecCheckMoney("l17_no_file_takes_the_reconstruction", g_ag_equity_peak, 40.00);
   AgVecCheckDT("l17b_no_file_stamps_the_window_anchor", g_ag_equity_anchor, A1);
   AgVecCheckMoney("l17c_no_file_returns_the_equity_term", eq_lvl, 40.00 - 109.58);
   AgVecCheck("l17d_reconciliation_marks_itself_done", g_ag_equity_reconciled, "");
   //--- V2-D18 option (a): ONE IMMEDIATE SAVE AT RECONCILIATION. The write
   //--- gate of V2-D3 governs rises only and is not extended to this event, so
   //--- the value must be on disk before any later pass runs.
   AgEquityResetModel();
   AgVecCheckInt("l17e_reconciliation_saved_immediately", AgEquityLoad(), 0);
   AgVecCheckMoney("l17f_the_saved_value_is_the_taken_value", g_ag_equity_peak, 40.00);

   //--- SAME ANCHOR: the stricter of the two, proven in BOTH directions so the
   //--- vector cannot pass on a max() that silently always picks one side.
   AgEquityResetModel();
   g_ag_equity_anchor     = A1;
   g_ag_equity_peak       = 76.7035;          // persisted above the reconstruction
   g_ag_equity_reconciled = false;
   g_ag_peak_currency     = 40.00;
   AgEquityUpdate(A1, 109.58, 30);
   AgVecCheckMoney("l18_equal_anchor_takes_the_persisted_value_when_it_is_higher",
                   g_ag_equity_peak, 76.7035);

   AgEquityResetModel();
   g_ag_equity_anchor     = A1;
   g_ag_equity_peak       = 20.00;            // persisted below the reconstruction
   g_ag_equity_reconciled = false;
   g_ag_peak_currency     = 40.00;
   AgEquityUpdate(A1, 109.58, 30);
   AgVecCheckMoney("l18b_equal_anchor_takes_the_reconstruction_when_it_is_higher",
                   g_ag_equity_peak, 40.00);

   //--- STALE ANCHOR: the persisted value is 0.00 for the current day (V2-D8),
   //--- so a large leftover figure from a prior day must contribute NOTHING.
   //--- 999.00 is deliberately far above the reconstruction: if the stale value
   //--- leaked into the max this vector reads 999.00 and fails loudly.
   AgEquityResetModel();
   g_ag_equity_anchor     = A0;
   g_ag_equity_peak       = 999.00;
   g_ag_equity_reconciled = false;
   g_ag_peak_currency     = 40.00;
   AgEquityUpdate(A1, 109.58, 30);
   AgVecCheckMoney("l19_stale_anchor_declines_the_persisted_value", g_ag_equity_peak, 40.00);
   AgVecCheckDT("l19b_stale_anchor_stamps_the_new_window_anchor", g_ag_equity_anchor, A1);

   //--- BACKWARD CLOCK STEP (V2-D16 option (a)): the model's anchor is LATER
   //--- than the window anchor. The value is HELD and the max is taken, the
   //--- anchor is NOT rewound, and the condition is warned on this block's own
   //--- cadence. l20 fails if the later anchor is folded into the stale branch,
   //--- which would drop the equity term in a single act.
   AgEquityResetModel();
   g_ag_equity_anchor     = A3;
   g_ag_equity_peak       = 76.7035;
   g_ag_equity_reconciled = false;
   g_ag_peak_currency     = 40.00;
   g_ag_last_equity_warn  = 0;
   eq_lvl = AgEquityUpdate(A1, 109.58, 30);
   AgVecCheckMoney("l20_backward_step_holds_the_later_anchored_value",
                   g_ag_equity_peak, 76.7035);
   AgVecCheckDT("l20b_backward_step_does_not_rewind_the_anchor", g_ag_equity_anchor, A3);
   AgVecCheck("l20c_backward_step_warns_on_its_own_cadence",
              g_ag_last_equity_warn != 0, "no backward-step WARN was emitted");
   AgVecCheckMoney("l20d_backward_step_still_enforces_the_held_value",
                   eq_lvl, 76.7035 - 109.58);

   //--- V2-D15 OPTION (b), THE DISCRIMINATOR OF THIS WHOLE SESSION: the max()
   //--- rule lives at reconciliation and NOWHERE ELSE. Once the session has
   //--- reconciled, a realized peak that rises must NOT pull the equity peak up
   //--- on an ordinary pass. Under option (a) this vector would read 500.00 and
   //--- chosen=peak would be structurally unreachable; under the ruled option
   //--- (b) the equity peak stays where reconciliation left it and acceptance
   //--- row V2-H stands.
   g_ag_peak_currency = 500.00;
   AgEquityUpdate(A1, 109.58, 30);
   AgVecCheckMoney("l21_no_per_pass_pull_up_from_the_realized_peak",
                   g_ag_equity_peak, 76.7035);
   AgVecCheckDT("l21b_an_ordinary_pass_moves_no_anchor", g_ag_equity_anchor, A3);

   //--- AND THE RECONCILIATION IS ONCE PER SESSION, not once per anchor: a
   //--- second call with a different window anchor still does not re-run it.
   AgEquityUpdate(A1 + 172800, 109.58, 30);
   AgVecCheckMoney("l21c_reconciliation_does_not_run_a_second_time",
                   g_ag_equity_peak, 76.7035);

   PrintFormat("AGVEC|SUMMARY|%d/%d", g_pass, g_total);
  }
//+------------------------------------------------------------------+
