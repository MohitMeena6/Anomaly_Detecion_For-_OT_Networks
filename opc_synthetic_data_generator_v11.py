import random
import os
import csv
import math
import datetime
from itertools import islice

# ─────────────────────────────────────────────────────────────────────────────
#  CONFIG
# ─────────────────────────────────────────────────────────────────────────────

TOTAL_ROWS  = 3_000_000
CHUNK_SIZE  = 500_000

OUTPUT_DIR  = "."
OUTPUT_FILE = os.path.join(OUTPUT_DIR, "opc_synthetic_dataset.csv")

CLASS_DISTRIBUTION = {
    0: 0.35,    # Normal
    1: 0.2167,  # Unauthorized_Access
    2: 0.2167,  # Tag_Modification
    3: 0.2166,  # New_Client
}

ATTACK_CONFIG = {
    0: {"label": 0, "label_str": "Normal"},
    1: {"label": 1, "label_str": "Unauthorized Access"},
    2: {"label": 2, "label_str": "Tag Modification Detected"},
    3: {"label": 3, "label_str": "New Client Detected Alert"},
}

# V11: label noise kept at 2.5% (unchanged from V10)
LABEL_NOISE_PROB = 0.025

# ─────────────────────────────────────────────────────────────────────────────
#  REFERENCE DATA  (all unchanged from V9)
# ─────────────────────────────────────────────────────────────────────────────

PROTOCOLS = ["OPC-UA", "OPC-DA", "OPC-UA/TCP", "OPC-UA/HTTPS"]

KNOWN_CLIENT_NAMES = [
    "Wonderware_InTouch", "Ignition_SCADA", "FactoryTalk_View",
    "Kepware_OPCServer", "RSLogix5000", "TIA_Portal_Client",
    "AspenTech_HMI", "GE_iFIX", "Citect_SCADA", "Inductive_Ignition",
]
CONTRACTOR_CLIENT_NAMES = [
    "VendorTech_Remote", "ABB_ServiceTool", "Siemens_PCS7_Client",
    "Emerson_DeltaV_WS", "Honeywell_PHD_Client", "Schneider_EcoStruxure",
]
UNKNOWN_CLIENT_NAMES = [
    "UnknownClient_XR91", "ScanBot_v2", "OPCProbe_alpha",
    "nmap_opc_scanner", "python-opcua", "opcua-client-gui",
    "anonymous_client", "TestNode_7743", "recon_agent_v1",
    "generic_opc_client", "Metasploit_OPC",
]

KNOWN_CLSIDS = [
    "{76C0A4B7-3C3D-11D0-8F2C-00A0C91A5B01}",
    "{63D5F432-CFE4-11d1-B2C8-0060083BA1FB}",
    "{13486D51-4821-11D2-A494-3CB306C10000}",
    "{E9F2213E-B5C6-4A79-9E72-3A5A3B2E4B29}",
]
UNKNOWN_CLSIDS = [
    "{00000000-0000-0000-0000-000000000000}",
    "{FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF}",
    "{DEADBEEF-DEAD-BEEF-DEAD-BEEFDEADBEEF}",
    "{11111111-2222-3333-4444-555555555555}",
]

OPC_SERVER_NAMES = [
    "OPC.SimaticNET.1", "Matrikon.OPC.Simulation.1",
    "Kepware.KEPServerEX.V6", "RSI.OPCServer.1",
    "GE.Proficy.OPCServer", "ABB.OPCServer.DA",
]

ENDPOINT_TEMPLATES = [
    "opc.tcp://192.168.{a}.{b}:4840",
    "opc.tcp://10.0.{a}.{b}:4840",
    "opc.tcp://172.16.{a}.{b}:4840",
]

TAG_NAMES = [
    "PLC1.Temperature_Reactor_A",  "PLC1.Pressure_Tank_B",
    "PLC2.FlowRate_Line_1",        "PLC2.Valve_Status_V01",
    "PLC3.Motor_Speed_RPM",        "PLC3.Conveyor_Belt_Status",
    "HMI.Setpoint_Temp_Max",       "HMI.Emergency_Stop_Flag",
    "SCADA.Alarm_Level_High",      "SCADA.Pump_RunStatus",
    "Field.LevelSensor_Tank_C",    "Field.PressureSensor_P02",
    "PLC4.Compressor_Outlet_Temp", "PLC4.Agitator_Speed",
    "HIST.BatchRecord_001",        "EWS.PatchStatus_Node7",
]
CRITICAL_TAGS = [
    "HMI.Emergency_Stop_Flag", "SCADA.Alarm_Level_High",
    "PLC1.SafetyInterlock_01",  "HMI.Setpoint_Temp_Max",
]
CALIBRATION_TAGS = [
    "PLC1.Temperature_Reactor_A", "PLC1.Pressure_Tank_B",
    "PLC2.FlowRate_Line_1", "PLC4.Compressor_Outlet_Temp",
    "Field.LevelSensor_Tank_C", "Field.PressureSensor_P02",
]

TAG_DATA_TYPES = ["Float", "Int32", "Boolean", "String", "Double", "UInt16"]

OPC_STATUS_OK  = ["Good", "Good_LocalOverride", "Good_CascadeInitializationAcknowledged"]
OPC_STATUS_BAD = [
    "Bad_UserAccessDenied", "Bad_SecurityChecksFailed",
    "Bad_InvalidArgument",  "Bad_SessionClosed",
    "Bad_NotConnected",     "Bad_UnexpectedError",
    "Bad_Timeout",          "Bad_EncodingError",
]
OPC_STATUS_UNCERTAIN = ["Uncertain_LastUsableValue", "Uncertain_SubNormal"]

ALL_SERVICES = [
    "Read", "Write", "Browse", "Subscribe", "Publish",
    "CreateSession", "ActivateSession", "CloseSession",
    "CreateMonitoredItems", "ModifyMonitoredItems",
]

# ─────────────────────────────────────────────────────────────────────────────
#  V9: DYNAMIC PROCESS STATE MODEL  (unchanged from V9)
# ─────────────────────────────────────────────────────────────────────────────

_BASE_PROCESS_STATE = {
    "PLC1.Temperature_Reactor_A" : {"setpoint": 180.0, "safe_delta": 12.0,  "partner": "PLC1.Pressure_Tank_B",        "drift_sigma": 3.5},
    "PLC1.Pressure_Tank_B"       : {"setpoint": 5.2,   "safe_delta": 0.8,   "partner": "PLC1.Temperature_Reactor_A",  "drift_sigma": 0.15},
    "PLC2.FlowRate_Line_1"       : {"setpoint": 120.0, "safe_delta": 20.0,  "partner": "PLC2.Valve_Status_V01",       "drift_sigma": 5.0},
    "PLC2.Valve_Status_V01"      : {"setpoint": 1.0,   "safe_delta": 0.1,   "partner": "PLC2.FlowRate_Line_1",        "drift_sigma": 0.0},
    "PLC3.Motor_Speed_RPM"       : {"setpoint": 1450.0,"safe_delta": 100.0, "partner": "PLC3.Conveyor_Belt_Status",   "drift_sigma": 25.0},
    "PLC3.Conveyor_Belt_Status"  : {"setpoint": 1.0,   "safe_delta": 0.0,   "partner": "PLC3.Motor_Speed_RPM",        "drift_sigma": 0.0},
    "HMI.Setpoint_Temp_Max"      : {"setpoint": 200.0, "safe_delta": 5.0,   "partner": "PLC1.Temperature_Reactor_A",  "drift_sigma": 1.0},
    "HMI.Emergency_Stop_Flag"    : {"setpoint": 0.0,   "safe_delta": 0.0,   "partner": "SCADA.Alarm_Level_High",      "drift_sigma": 0.0},
    "SCADA.Alarm_Level_High"     : {"setpoint": 0.0,   "safe_delta": 0.0,   "partner": "HMI.Emergency_Stop_Flag",     "drift_sigma": 0.0},
    "SCADA.Pump_RunStatus"       : {"setpoint": 1.0,   "safe_delta": 0.0,   "partner": "PLC2.FlowRate_Line_1",        "drift_sigma": 0.0},
    "Field.LevelSensor_Tank_C"   : {"setpoint": 75.0,  "safe_delta": 10.0,  "partner": "PLC2.Valve_Status_V01",       "drift_sigma": 2.5},
    "Field.PressureSensor_P02"   : {"setpoint": 3.8,   "safe_delta": 0.5,   "partner": "PLC1.Pressure_Tank_B",        "drift_sigma": 0.1},
    "PLC4.Compressor_Outlet_Temp": {"setpoint": 65.0,  "safe_delta": 8.0,   "partner": "PLC4.Agitator_Speed",         "drift_sigma": 2.0},
    "PLC4.Agitator_Speed"        : {"setpoint": 280.0, "safe_delta": 40.0,  "partner": "PLC4.Compressor_Outlet_Temp", "drift_sigma": 10.0},
    "HIST.BatchRecord_001"       : {"setpoint": 0.0,   "safe_delta": 100.0, "partner": "PLC1.Temperature_Reactor_A",  "drift_sigma": 0.0},
    "EWS.PatchStatus_Node7"      : {"setpoint": 1.0,   "safe_delta": 0.0,   "partner": "HIST.BatchRecord_001",        "drift_sigma": 0.0},
}

_OP_MODES = ["STEADY_STATE", "STARTUP", "RAMP_DOWN", "REDUCED_LOAD", "MAINTENANCE_MODE"]
_OP_MODE_MODIFIERS = {
    "STEADY_STATE"    : {"setpoint_mult": 1.00, "delta_mult": 1.00},
    "STARTUP"         : {"setpoint_mult": 0.65, "delta_mult": 1.40},
    "RAMP_DOWN"       : {"setpoint_mult": 0.80, "delta_mult": 1.25},
    "REDUCED_LOAD"    : {"setpoint_mult": 0.90, "delta_mult": 1.15},
    "MAINTENANCE_MODE": {"setpoint_mult": 0.50, "delta_mult": 2.00},
}

def _sample_dynamic_setpoint(tag: str, op_mode: str = "STEADY_STATE"):
    ps = _BASE_PROCESS_STATE.get(tag)
    if ps is None:
        return None, None
    mod = _OP_MODE_MODIFIERS.get(op_mode, _OP_MODE_MODIFIERS["STEADY_STATE"])
    setpoint = ps["setpoint"] * mod["setpoint_mult"]
    drift = random.gauss(0, ps["drift_sigma"]) if ps["drift_sigma"] > 0 else 0.0
    setpoint = max(0.0, setpoint + drift)
    safe_delta = ps["safe_delta"] * mod["delta_mult"]
    if random.random() < 0.05:
        safe_delta *= random.uniform(1.2, 1.6)
    return setpoint, safe_delta


def _rng_tag_value_semantic(tag: str, dtype: str, severity: float,
                             attack_mode: str = "none", op_mode: str = "STEADY_STATE",
                             drift_sign: int = 1):
    """
    V11: Process-state-aware tag value generation with long-horizon semantic consequence.

    KEY V11 INNOVATION — process_health_delta:
      Returned as a 6th value. Encodes whether the write CONVERGED toward setpoint
      (positive, maintenance intent) or DIVERGED from setpoint (negative, attack intent).

      Normal / Maintenance writes:  process_health_delta > 0  (corrective, stabilizing)
      Stealth attack writes:        process_health_delta < 0  (divergent, degrading)
      CAMOUFLAGE / MAINT_BLEND:     small magnitude (locally ambiguous)

    The IDS can learn this causal signal across sessions — it is the PRIMARY
    long-horizon distinguisher that V10 was missing.
    """
    setpoint, safe_delta = _sample_dynamic_setpoint(tag, op_mode)
    if setpoint is None or dtype not in ("Float", "Double", "Int32", "UInt16"):
        bv, av, d, pct = _rng_tag_value(dtype, severity)
        if attack_mode == "none":
            legality = random.gauss(0.90, 0.08)
            phd = round(random.gauss(0.12, 0.08), 4)   # maintenance: convergent
        elif attack_mode in ("camouflage", "coherent_drift"):
            legality = random.gauss(0.72, 0.12)
            # camouflage: tiny negative (hidden divergence — locally looks corrective)
            phd = round(random.gauss(-0.04, 0.06), 4)
        elif attack_mode in ("gradual", "stealthy"):
            legality = random.gauss(0.55, 0.18)
            phd = round(random.gauss(-0.12, 0.08), 4)  # attack: divergent
        else:
            legality = random.gauss(0.20, 0.18)
            phd = round(random.gauss(-0.35, 0.12), 4)  # obvious: strongly divergent
        return bv, av, d, pct, round(max(0.0, min(1.0, legality)), 4), round(max(-1.0, min(1.0, phd)), 4)

    if dtype in ("Float", "Double"):
        noise = random.gauss(0, safe_delta * 0.35)
        before = round(max(0.0, setpoint + noise), 4)
        before_deviation = abs(before - setpoint)

        if attack_mode == "none":
            # MAINTENANCE INTENT: writes push value TOWARD setpoint (corrective)
            # If before > setpoint, write moves it down; if before < setpoint, moves up
            if random.random() < 0.70:
                # Corrective write: move toward setpoint
                direction = -1.0 if (before > setpoint) else 1.0
                correction_frac = random.uniform(0.30, 0.80)
                change = direction * before_deviation * correction_frac + random.gauss(0, safe_delta * 0.10)
            else:
                # Small neutral adjustment (normal operational variance)
                change = random.gauss(0, safe_delta * 0.25)
            after = round(max(0.0, before + change), 4)
            after_deviation = abs(after - setpoint)
            # process_health_delta: positive when after is closer to setpoint than before
            phd = round((before_deviation - after_deviation) / max(safe_delta, 0.001), 4)
            phd = round(max(-1.0, min(1.0, phd + random.gauss(0, 0.04))), 4)
            deviation_ratio = after_deviation / max(safe_delta, 0.001)
            legality = max(0.0, 1.0 - deviation_ratio * 0.30)
            legality = round(min(1.0, max(0.0, legality + random.gauss(0, 0.05))), 4)

        elif attack_mode == "gradual":
            # Moderate attack: writes push slightly AWAY from setpoint
            stay_inside = random.random() < 0.70
            if stay_inside:
                drift = random.uniform(safe_delta * 0.2, safe_delta * 0.85)
                after = round(max(0.0, before + random.choice([-1, 1]) * drift), 4)
                deviation_ratio = abs(after - setpoint) / max(safe_delta, 0.001)
                legality = max(0.4, 1.0 - deviation_ratio * 0.5)
            else:
                drift = random.uniform(safe_delta * 0.9, safe_delta * 1.6)
                after = round(max(0.0, before + random.choice([-1, 1]) * drift), 4)
                deviation_ratio = abs(after - setpoint) / max(safe_delta, 0.001)
                legality = max(0.1, 1.0 - deviation_ratio * 0.7)
            legality = round(min(1.0, max(0.0, legality + random.gauss(0, 0.06))), 4)
            after_deviation = abs(after - setpoint)
            phd = round((before_deviation - after_deviation) / max(safe_delta, 0.001), 4)
            # Gradual attacks: phd biased negative (divergent) but with noise
            phd = round(max(-1.0, min(1.0, phd - random.uniform(0.05, 0.20) + random.gauss(0, 0.06))), 4)

        elif attack_mode == "stealthy":
            # Stealthy: pushes slightly outside safe_delta; process_health_delta negative
            push_frac = random.uniform(0.75, 1.10)
            push = safe_delta * push_frac
            after = round(max(0.0, before + random.choice([-1, 1]) * push), 4)
            deviation_ratio = abs(after - setpoint) / max(safe_delta, 0.001)
            legality = max(0.25, 1.0 - deviation_ratio * 0.6)
            legality = round(min(1.0, max(0.0, legality + random.gauss(0, 0.08))), 4)
            after_deviation = abs(after - setpoint)
            phd = round((before_deviation - after_deviation) / max(safe_delta, 0.001), 4)
            phd = round(max(-1.0, min(1.0, phd - random.uniform(0.08, 0.25) + random.gauss(0, 0.07))), 4)

        elif attack_mode == "camouflage":
            # V11 CAMOUFLAGE: stays inside safe_delta but writes biased AWAY from setpoint.
            # Locally looks like calibration. Globally creates slow divergence.
            # Small negative phd that accumulates over sessions.
            if random.random() < 0.55:
                # Appear corrective (deceptive stabilization — Fix 6)
                direction = -1.0 if (before > setpoint) else 1.0
                correction_frac = random.uniform(0.10, 0.35)  # partial correction only
                calib_change = direction * before_deviation * correction_frac + random.gauss(0, safe_delta * 0.12)
                # But then add a tiny hidden counter-nudge
                hidden_nudge = drift_sign * random.uniform(0, safe_delta * 0.08)
                after = round(max(0.0, before + calib_change + hidden_nudge), 4)
            else:
                # Random-seeming write that subtly drifts
                calib_change = drift_sign * random.uniform(safe_delta * 0.05, safe_delta * 0.28)
                after = round(max(0.0, before + calib_change), 4)
            deviation_ratio = abs(after - setpoint) / max(safe_delta, 0.001)
            legality = max(0.55, 1.0 - deviation_ratio * 0.30)
            legality = round(min(1.0, max(0.0, legality + random.gauss(0, 0.04))), 4)
            after_deviation = abs(after - setpoint)
            phd = round((before_deviation - after_deviation) / max(safe_delta, 0.001), 4)
            # Small negative bias — locally ambiguous, globally a weak signal
            phd = round(max(-1.0, min(1.0, phd - random.uniform(0.02, 0.10) + random.gauss(0, 0.05))), 4)

        elif attack_mode == "coherent_drift":
            # V11 COHERENT_DRIFT: directional nudge, biased AWAY from setpoint.
            # Individually within safe_delta (plausible). Collectively diverges.
            # process_health_delta consistently small-negative per write.
            nudge = drift_sign * random.uniform(safe_delta * 0.08, safe_delta * 0.38)
            after = round(max(0.0, before + nudge), 4)
            deviation_ratio = abs(after - setpoint) / max(safe_delta, 0.001)
            legality = max(0.50, 1.0 - deviation_ratio * 0.25)
            legality = round(min(1.0, max(0.0, legality + random.gauss(0, 0.05))), 4)
            after_deviation = abs(after - setpoint)
            phd = round((before_deviation - after_deviation) / max(safe_delta, 0.001), 4)
            # Coherent drift: consistently negative phd (drifting away from setpoint)
            phd = round(max(-1.0, min(1.0, phd - random.uniform(0.03, 0.15) + random.gauss(0, 0.04))), 4)

        else:  # obvious / moderate
            if random.random() < 0.15:
                blast = safe_delta * random.uniform(1.2, 2.5)
                legality_base = 0.25
            else:
                blast = safe_delta * random.uniform(2.5, 7.0) * (0.5 + severity)
                legality_base = 0.05
            after = round(max(0.0, before + random.choice([-1, 1]) * blast), 4)
            legality = round(max(0.0, legality_base + random.gauss(0, 0.08)), 4)
            after_deviation = abs(after - setpoint)
            phd = round((before_deviation - after_deviation) / max(safe_delta, 0.001), 4)
            # Obvious attacks: strongly negative phd
            phd = round(max(-1.0, min(1.0, phd - random.uniform(0.30, 0.60))), 4)

        delta = round(abs(after - before), 4)
        pct = round(delta / before * 100, 2) if before > 0 else 0.0
        if severity < 0.25 and pct > 0:
            pct = round(max(0.0, pct + random.gauss(0, 0.5) * pct), 2)
        return before, after, delta, pct, legality, round(max(-1.0, min(1.0, phd)), 4)

    bv, av, d, pct = _rng_tag_value(dtype, severity)
    if attack_mode == "none":
        legality = round(max(0.0, min(1.0, random.gauss(0.88, 0.08))), 4)
        phd = round(max(-1.0, min(1.0, random.gauss(0.10, 0.07))), 4)
    elif attack_mode in ("gradual", "stealthy", "camouflage", "coherent_drift"):
        legality = round(max(0.0, min(1.0, random.gauss(0.65, 0.16))), 4)
        phd = round(max(-1.0, min(1.0, random.gauss(-0.08, 0.07))), 4)
    else:
        legality = round(max(0.0, min(1.0, random.gauss(0.20, 0.18))), 4)
        phd = round(max(-1.0, min(1.0, random.gauss(-0.38, 0.12))), 4)
    return bv, av, d, pct, legality, phd


# ── V8/V9: Service Transition Probability Matrix (unchanged) ──────────────
_SVC_IDX = {s: i for i, s in enumerate(ALL_SERVICES)}
_N_SVC = len(ALL_SERVICES)
_TRANS_PROB = [
    # Read  Wri  Bro  Sub  Pub  CrS  AcS  ClS  CMI  MMI
    [0.35, 0.10, 0.15, 0.20, 0.08, 0.02, 0.01, 0.04, 0.03, 0.02],
    [0.30, 0.25, 0.05, 0.10, 0.12, 0.01, 0.01, 0.08, 0.05, 0.03],
    [0.30, 0.05, 0.30, 0.15, 0.05, 0.03, 0.02, 0.05, 0.04, 0.01],
    [0.10, 0.02, 0.05, 0.15, 0.60, 0.01, 0.01, 0.03, 0.02, 0.01],
    [0.08, 0.02, 0.03, 0.10, 0.65, 0.01, 0.01, 0.06, 0.02, 0.02],
    [0.10, 0.02, 0.10, 0.05, 0.02, 0.05, 0.60, 0.02, 0.02, 0.02],
    [0.30, 0.05, 0.25, 0.15, 0.05, 0.02, 0.05, 0.05, 0.05, 0.03],
    [0.05, 0.02, 0.02, 0.02, 0.02, 0.80, 0.03, 0.01, 0.01, 0.02],
    [0.10, 0.05, 0.05, 0.55, 0.15, 0.01, 0.01, 0.03, 0.03, 0.02],
    [0.10, 0.05, 0.05, 0.50, 0.20, 0.01, 0.01, 0.03, 0.03, 0.02],
]

def _transition_rarity(prev_service: str, curr_service: str) -> float:
    if prev_service not in _SVC_IDX or curr_service not in _SVC_IDX:
        return 0.5
    prob = _TRANS_PROB[_SVC_IDX[prev_service]][_SVC_IDX[curr_service]]
    return round(max(0.0, min(1.0, 1.0 - prob * 3.0)), 4)


# ── V9: Persistent Remote Operator Pool (unchanged) ───────────────────────
_REMOTE_OPERATORS = [
    {"username": "eng_user_1",         "auth": "Certificate", "privilege": "Engineer",      "ip_prefix": "10.0.2",     "seen_baseline": 450},
    {"username": "eng_user_3",         "auth": "Certificate", "privilege": "Engineer",      "ip_prefix": "10.0.3",     "seen_baseline": 280},
    {"username": "op_user_5",          "auth": "Username",    "privilege": "Operator",      "ip_prefix": "192.168.1",  "seen_baseline": 820},
    {"username": "op_user_12",         "auth": "Username",    "privilege": "Operator",      "ip_prefix": "192.168.2",  "seen_baseline": 615},
    {"username": "vendor_2",           "auth": "Certificate", "privilege": "ReadOnly",      "ip_prefix": "172.16.1",   "seen_baseline": 95},
    {"username": "vendor_4",           "auth": "Username",    "privilege": "ReadOnly",      "ip_prefix": "10.0.5",     "seen_baseline": 72},
    {"username": "scada_svc_1",        "auth": "Certificate", "privilege": "Administrator", "ip_prefix": "192.168.10", "seen_baseline": 1200},
    {"username": "scada_svc_2",        "auth": "Certificate", "privilege": "Administrator", "ip_prefix": "192.168.11", "seen_baseline": 1050},
    {"username": "contractor_3",       "auth": "Username",    "privilege": "Operator",      "ip_prefix": "10.0.8",     "seen_baseline": 38},
    {"username": "contractor_7",       "auth": "Certificate", "privilege": "Engineer",      "ip_prefix": "10.0.9",     "seen_baseline": 55},
    {"username": "eng_user_6",         "auth": "Certificate", "privilege": "Engineer",      "ip_prefix": "172.16.2",   "seen_baseline": 190},
    {"username": "op_user_18",         "auth": "Username",    "privilege": "Operator",      "ip_prefix": "192.168.5",  "seen_baseline": 340},
    {"username": "calibration_tech_1", "auth": "Certificate", "privilege": "Engineer",      "ip_prefix": "10.0.12",    "seen_baseline": 85},
    {"username": "process_eng_2",      "auth": "Certificate", "privilege": "Engineer",      "ip_prefix": "10.0.13",    "seen_baseline": 140},
    {"username": "maint_tech_4",       "auth": "Username",    "privilege": "Operator",      "ip_prefix": "192.168.3",  "seen_baseline": 210},
]

def _pick_remote_operator():
    return random.choice(_REMOTE_OPERATORS)


def _inject_env_chaos(row: dict, ctx: dict, class_label: int = 0) -> dict:
    """V9: chaos applied to all classes. Unchanged from V9."""
    chaos_p = {0: 0.13, 1: 0.10, 2: 0.09, 3: 0.10}.get(class_label, 0.10)
    if random.random() > chaos_p:
        return row
    chaos_type = random.choices(
        ["response_spike", "bad_status", "empty_payload", "auth_miss",
         "retry_storm", "contradictory_write", "abandoned_partial"],
        weights=[28, 22, 15, 12, 10, 8, 5], k=1
    )[0]
    if chaos_type == "response_spike":
        row["response_time_ms"] = int(row.get("response_time_ms", 50) * random.uniform(4, 25))
    elif chaos_type == "bad_status":
        row["opc_status_code"] = random.choice(OPC_STATUS_BAD)
    elif chaos_type == "empty_payload":
        row["payload_size_bytes"] = 0
    elif chaos_type == "auth_miss":
        row["failed_auth_count"] = int(row.get("failed_auth_count", 0)) + random.randint(1, 4)
    elif chaos_type == "retry_storm":
        row["requests_per_minute"] = int(row.get("requests_per_minute", 12) * random.uniform(3, 8))
        row["response_time_ms"] = int(row.get("response_time_ms", 50) * random.uniform(2, 6))
    elif chaos_type == "contradictory_write":
        row["write_ops_in_window"] = int(row.get("write_ops_in_window", 0)) + random.randint(3, 12)
        row["unique_tags_accessed"] = int(row.get("unique_tags_accessed", 1)) + random.randint(1, 5)
    elif chaos_type == "abandoned_partial":
        row["connection_duration_ms"] = random.randint(50, 500)
        row["opc_status_code"] = random.choice(["Bad_SessionClosed", "Bad_Timeout"])
    return row


SECURITY_MODES    = ["None", "Sign", "SignAndEncrypt"]
SECURITY_POLICIES = ["None", "Basic128Rsa15", "Basic256", "Basic256Sha256", "Aes128_Sha256_RsaOaep"]
AUTH_METHODS      = ["Anonymous", "Username", "Certificate", "IssuedToken"]
PRIVILEGE_LEVELS  = ["Operator", "Engineer", "Administrator", "ReadOnly", "Guest"]
USER_DOMAINS      = ["CORP", "OT_NET", "WORKGROUP", "LOCAL", "SCADA_DOMAIN"]

_PRIV_IPS = (
    [f"192.168.{a}.{b}" for a in range(1, 11) for b in range(2, 255)] +
    [f"10.0.{a}.{b}"    for a in range(0, 21) for b in range(2, 255)] +
    [f"172.16.{a}.{b}"  for a in range(0, 6)  for b in range(2, 255)]
)
_PUB_IPS = [
    f"{a}.{b}.{c}.{d}"
    for a in range(1, 30) for b in range(0, 256, 17)
    for c in [0, 128]    for d in range(1, 255, 7)
]


# ─────────────────────────────────────────────────────────────────────────────
#  HELPERS  (unchanged from V9)
# ─────────────────────────────────────────────────────────────────────────────

def _rng_ip(private: bool = True) -> str:
    return random.choice(_PRIV_IPS if private else _PUB_IPS)

def _rng_port(high_range: bool = False) -> int:
    return random.randint(49152, 65535) if high_range else random.choice(
        [4840, 4843, 4880, 4881, random.randint(1024, 49151)])

def _rng_cert_thumb() -> str:
    return os.urandom(20).hex().upper()

def _endpoint() -> str:
    t = random.choice(ENDPOINT_TEMPLATES)
    return t.format(a=random.randint(1, 10), b=random.randint(2, 254))

def _rng_timestamp(hour_range=None) -> str:
    base = datetime.datetime(2023, 1, 1)
    secs = random.randint(0, 2 * 365 * 24 * 3600)
    ts   = base + datetime.timedelta(seconds=secs)
    hour = random.randint(*hour_range) if hour_range else random.randint(0, 23)
    ts = ts.replace(hour=hour, minute=random.randint(0, 59), second=random.randint(0, 59))
    return ts.strftime("%Y-%m-%d %H:%M:%S.") + f"{random.randint(0,999):03d}"

def _temporal_context():
    hour    = random.randint(0, 23)
    weekday = random.randint(0, 6)
    is_shift_change   = hour in (6, 7, 14, 15, 22, 23)
    is_business_hours = 7 <= hour <= 19 and weekday < 5
    is_weekend        = weekday >= 5
    is_maintenance    = (not is_business_hours) and (is_weekend or hour < 6)
    is_peak_prod      = is_business_hours and (8 <= hour <= 11 or 13 <= hour <= 17)
    if 7 <= hour < 15:      shift_id = 0
    elif 15 <= hour < 23:   shift_id = 1
    else:                   shift_id = 2
    is_historian_sync  = 2 <= hour <= 4
    is_ramp_period     = hour in (6, 7, 8, 17, 18, 19)
    is_backup_window   = is_weekend and 1 <= hour <= 3
    is_patching_window = weekday in (0, 3) and 2 <= hour <= 5
    is_alarm_risk      = hour in (13, 14, 21, 22) and not is_weekend
    reduced_staffing   = shift_id == 2 and not is_weekend
    if shift_id == 2 and not is_maintenance:
        if random.random() < 0.15:
            is_maintenance = True
    if is_maintenance:
        op_mode = "MAINTENANCE_MODE"
    elif is_ramp_period:
        op_mode = random.choice(["STARTUP", "RAMP_DOWN", "STEADY_STATE"])
    elif is_peak_prod:
        op_mode = "STEADY_STATE"
    elif is_weekend:
        op_mode = random.choice(["REDUCED_LOAD", "MAINTENANCE_MODE"])
    else:
        op_mode = random.choices(["STEADY_STATE", "REDUCED_LOAD", "STARTUP"], weights=[70, 20, 10], k=1)[0]
    return {
        "hour": hour, "weekday": weekday,
        "is_business_hours": is_business_hours, "is_maintenance": is_maintenance,
        "is_peak_prod": is_peak_prod, "is_shift_change": is_shift_change,
        "is_weekend": is_weekend, "outside_hours": not is_business_hours,
        "shift_id": shift_id, "is_historian_sync": is_historian_sync,
        "is_ramp_period": is_ramp_period, "is_backup_window": is_backup_window,
        "is_patching_window": is_patching_window, "is_alarm_risk": is_alarm_risk,
        "reduced_staffing": reduced_staffing, "op_mode": op_mode,
    }

def _stealth_temporal_context():
    ctx = _temporal_context()
    if random.random() < 0.35:
        ctx.update({"is_maintenance": True, "outside_hours": True,
                    "is_business_hours": False, "op_mode": "MAINTENANCE_MODE"})
        if ctx["shift_id"] != 2:
            ctx["shift_id"] = random.choice([1, 2])
        ctx["hour"] = random.choice(list(range(0, 6)) + [22, 23])
        ctx["reduced_staffing"] = (ctx["shift_id"] == 2)
    elif random.random() < 0.20:
        ctx.update({"is_historian_sync": True, "shift_id": 2,
                    "reduced_staffing": True, "op_mode": "REDUCED_LOAD"})
        ctx["hour"] = random.choice([2, 3, 4])
    return ctx

def _ts_from_context(ctx) -> str:
    if ctx.get("is_historian_sync", False):
        hr = random.choice([2, 3, 4])
        return _rng_timestamp(hour_range=(hr, hr))
    elif ctx["is_maintenance"]:
        return _rng_timestamp(hour_range=(1, 5))
    elif ctx["outside_hours"]:
        hr = random.choice(list(range(0, 7)) + list(range(20, 24)))
        return _rng_timestamp(hour_range=(hr, hr))
    elif ctx["is_shift_change"]:
        hr = random.choice([6, 7, 14, 15, 22, 23])
        return _rng_timestamp(hour_range=(hr, hr))
    else:
        return _rng_timestamp(hour_range=(7, 19))

def _rng_tag_value(dtype: str, severity: float = 0.0):
    if dtype == "Boolean":
        before = random.randint(0, 1)
        flip   = random.random() < (0.1 + 0.9 * severity)
        after  = (1 - before) if flip else before
        return before, after, abs(after - before), float(abs(after - before) * 100)
    if dtype in ("Float", "Double"):
        before = round(random.uniform(10.0, 500.0), 4)
        if severity > 0.7:       delta = random.uniform(100.0, 400.0)
        elif severity > 0.25:
            t = (severity - 0.25) / 0.45
            delta = random.uniform(0.5, 12.0) + t * (random.uniform(12.0, 50.0) - random.uniform(0.5, 12.0))
        elif severity > 0.10:    delta = random.uniform(0.5, 12.0)
        else:                    delta = random.uniform(0.01, 4.0)
        after = round(before + random.choice([-1, 1]) * delta, 4)
        delta = round(abs(after - before), 4)
        pct   = round(delta / before * 100, 2) if before else 0.0
        if severity < 0.25 and pct > 0:
            pct = round(max(0.0, pct + random.gauss(0, 0.5) * pct), 2)
        return before, after, delta, pct
    if dtype in ("Int32", "UInt16"):
        before = random.randint(0, 1000)
        if severity > 0.7:    after = random.randint(2000, 9999)
        elif severity > 0.25: after = max(0, before + random.randint(50, 500) * random.choice([-1, 1]))
        elif severity > 0.10:
            dv = max(1, min(45, int(math.exp(random.gauss(math.log(8), 1.2)))))
            after = max(0, before + random.choice([-1, 1]) * dv)
        else:                 after = max(0, before + random.randint(-20, 20))
        delta = abs(after - before)
        return before, after, delta, round(delta / before * 100, 2) if before else 0.0
    before = f"STATE_{random.randint(1,5)}"
    after  = f"STATE_{random.randint(6,9)}" if severity > 0.5 else before
    return before, after, 0, 0.0

def _security_posture(legacy_prob: float = 0.15):
    if random.random() < legacy_prob:
        mode = random.choice(["None", "Sign"])
        policy = "None" if mode == "None" else "Basic128Rsa15"
        auth = random.choice(["Anonymous", "Username"]); cert = random.random() < 0.2
    else:
        mode = random.choice(["Sign", "Sign", "SignAndEncrypt"])
        policy = random.choice(["Basic256", "Basic256Sha256", "Aes128_Sha256_RsaOaep"])
        auth = random.choice(["Username", "Certificate", "Certificate"]); cert = True
    return auth, mode, policy, cert

def _lognormal_int(mu, sigma, lo, hi):
    return max(lo, min(hi, int(math.exp(random.gauss(math.log(max(mu, 1)), sigma)))))

def _base_row() -> dict:
    return {
        "timestamp": "", "src_ip": "", "dst_ip": "", "src_port": "", "dst_port": "",
        "protocol": random.choice(PROTOCOLS), "session_id": os.urandom(16).hex(),
        "connection_duration_ms": "", "opc_client_name": "", "opc_client_clsid": "",
        "opc_server_name": random.choice(OPC_SERVER_NAMES),
        "opc_server_endpoint_url": "", "opc_server_node_id": f"ns=2;i={random.randint(1000,9999)}",
        "client_certificate_thumbprint": "", "authentication_method": "",
        "security_mode": "", "security_policy": "", "opc_service_type": "",
        "opc_request_id": str(random.randint(100000, 999999)), "opc_status_code": "",
        "response_time_ms": "", "payload_size_bytes": "", "tag_name": "",
        "tag_node_id": f"ns=2;i={random.randint(1000,9999)}", "tag_data_type": "",
        "tag_value_before": "", "tag_value_after": "", "tag_quality": "Good",
        "tag_access_rights": "ReadWrite", "value_change_delta": "", "value_change_percent": "",
        "username": "", "user_domain": random.choice(USER_DOMAINS), "login_status": "",
        "failed_auth_count": 0, "privilege_level": "", "session_activation_result": "Success",
        "is_new_client": 0, "client_first_seen_timestamp": "", "client_seen_count": "",
        "requests_per_minute": "", "unique_tags_accessed": "", "write_ops_in_window": "",
        "access_outside_business_hours": 0, "geo_location_mismatch": 0,
        "client_known_to_whitelist": 1, "hour_of_day": 0, "shift_id": 0,
        "business_hours": 0, "maintenance_window": 0, "is_weekend": 0,
        "activity_burst_score": 0.0, "session_interarrival_ms": 0,
        "operational_load_score": 0.0, "session_duration_total": 0,
        "session_request_variance": 0.0, "session_write_ratio": 0.0,
        "session_unique_tags": 0, "session_behavior_entropy": 0.0,
        "session_event_index": 0, "session_state_transition_count": 0,
        "session_idle_gap_ms": 0, "session_temporal_drift": 0.0,
        "action_transition_rarity": 0.0, "value_semantic_legality": 1.0,
        "process_health_delta": 0.0, "session_process_convergence": 0.0,
        "cumulative_process_deviation": 0.0,
        "attack_chain_phase": "", "label": "", "label_str": "", "behavioral_profile": "",
    }


# ─────────────────────────────────────────────────────────────────────────────
#  SESSION STATE ENGINE  (V9 logic preserved; V10 adds TagMod-specific arcs)
# ─────────────────────────────────────────────────────────────────────────────

def _make_session_arc(n_rows: int, session_type: str, ctx: dict = None,
                      session_meta: dict = None) -> list:
    """
    V10 additions:
    - "attack_stealth_maint" arc type: produces phases identical to normal_maint
    - "attack_ultra_slow" arc: very long dwell with rare isolated writes
    - "attack_phantom" arc: zero writes — pure dwell/monitoring
    - session_meta dict carries per-session context (drift_sign, etc.)
    - Non-write rows in all stealth arcs use Normal_OPS service weights exactly
    - Write rows always separated by at least one read/idle row
    """
    arc = []
    total_dur = _lognormal_int(3000, 1.1, 200, 60000)
    ctx = ctx or {}
    session_meta = session_meta or {}

    # V10: Stealth TagMod arcs use Normal_OPS inter_base exactly (Failure 8 fix)
    if session_type in ("attack_stealth_maint", "attack_ultra_slow", "attack_phantom",
                        "attack_camouflage"):
        # Draw from Normal OPS distribution — attacker paces like an engineer
        inter_base = _lognormal_int(800, 0.9, 50, 5000)
        # Apply same context modifiers as normal
        if ctx.get("shift_id") == 2:
            inter_base = int(inter_base * 1.6)
        elif ctx.get("is_historian_sync"):
            inter_base = int(inter_base * 0.7)
        elif ctx.get("is_shift_change"):
            inter_base = int(inter_base * 0.6)
    elif session_type.startswith("attack"):
        pacing_mode = random.choices(
            ["slow_cautious", "normal_blend", "fast_aggressive"],
            weights=[40, 35, 25], k=1
        )[0]
        if pacing_mode == "slow_cautious":
            inter_base = _lognormal_int(3000, 1.2, 500, 20000)
        elif pacing_mode == "normal_blend":
            inter_base = _lognormal_int(900, 0.9, 100, 5000)
        else:
            inter_base = _lognormal_int(80, 0.8, 10, 400)
    else:
        inter_base = _lognormal_int(800, 0.9, 50, 5000)
        if ctx.get("shift_id") == 2:     inter_base = int(inter_base * 1.6)
        elif ctx.get("is_historian_sync"): inter_base = int(inter_base * 0.7)
        elif ctx.get("is_shift_change"):   inter_base = int(inter_base * 0.6)
        elif ctx.get("is_peak_prod"):      inter_base = int(inter_base * 0.9)

    drift_direction = random.choice([-1, 0, 0, 1])
    drift_magnitude = random.uniform(0.02, 0.25)

    # ── Phase construction ─────────────────────────────────────────────────

    if session_type == "attack_recon":
        phases = (["browse"] * max(1, n_rows // 3) +
                  ["read"]   * max(1, n_rows // 3) +
                  ["probe"]  * max(1, n_rows - 2*(n_rows//3)))

    elif session_type == "attack_probe":
        phases = (["auth"]     * max(1, n_rows // 4) +
                  ["read"]     * max(1, n_rows // 6) +
                  ["escalate"] * max(1, n_rows // 5) +
                  ["persist"]  * max(1, n_rows // 4) +
                  ["cleanup"]  * max(1, n_rows - n_rows*4//5))

    elif session_type == "attack_persist":
        phases = (["browse"] * max(1, 1) +
                  ["read"]   * max(1, n_rows // 5) +
                  ["write"]  * max(1, n_rows * 3//5) +
                  ["read"]   * max(1, n_rows // 8) +
                  ["idle"]   * max(1, n_rows - n_rows*4//5 - 2))
        ramp_len = random.randint(1, 2) if n_rows >= 5 else 0
        for k in range(ramp_len):
            if k < len(phases): phases[k] = "read"
        if n_rows >= 8 and random.random() < 0.30:
            pl = random.randint(1, min(3, n_rows // 4))
            ps_start = random.randint(n_rows // 4, max(n_rows // 4 + 1, 2 * n_rows // 4))
            for k in range(pl):
                if ps_start + k < len(phases): phases[ps_start + k] = "read"

    elif session_type == "attack_gradual":
        idle_pre = 0
        if random.random() < 0.50 and n_rows >= 5:
            idle_pre = random.randint(1, max(1, n_rows // 4))
        remaining = n_rows - idle_pre
        write_phases = ["write" if random.random() < 0.22 else "read" for _ in range(remaining)]
        if "write" not in write_phases and remaining > 0:
            write_phases[max(1, remaining // 2)] = "write"
        phases = ["idle"] * idle_pre + write_phases

    elif session_type == "attack_camouflage":
        phases = (["browse"] * max(1, n_rows // 6) +
                  ["read"]   * max(1, n_rows // 5) +
                  ["write"]  * max(1, n_rows * 2//5) +
                  ["read"]   * max(1, n_rows // 5) +
                  ["idle"]   * max(1, n_rows - n_rows*9//10))

    elif session_type == "attack_stealth_maint":
        # V10 NEW (Failure 1, 3): Phases identical to normal_maint.
        # Attacker is inside a legitimate maintenance session — same sequence as engineer.
        phases = (["login"] +
                  ["read"]   * max(1, n_rows // 6) +
                  ["write"]  * max(1, n_rows * 2 // 5) +
                  ["browse"] * max(1, n_rows // 5) +
                  ["read"]   * max(1, n_rows - n_rows*3//5 - 1))
        # Inject human gaps same as normal_maint
        if n_rows >= 6 and random.random() < 0.25:
            gap_pos = random.randint(2, max(2, n_rows // 2))
            if gap_pos < len(phases):
                phases[gap_pos] = random.choice(["browse", "read"])
        # V10: Ensure writes are NOT consecutive — human pacing (Failure 6 fix)
        _sep_phases = list(phases)
        for k in range(1, len(_sep_phases)):
            if _sep_phases[k] == "write" and _sep_phases[k-1] == "write":
                _sep_phases[k-1] = "read"  # interleave read between writes
        phases = _sep_phases

    elif session_type == "attack_ultra_slow":
        # V10 NEW (Failure 2): Redesigned ULTRA_SLOW arc.
        # Long dwell with reads. Writes are rare isolated single events.
        # Separated by 5-10 read/idle rows — impossible to detect from write ratio alone.
        # Phase pattern: many reads/idles, then one isolated write, then many more reads.
        n_writes = max(1, n_rows // 10)  # ~10% write rows
        n_writes = min(n_writes, 3)       # absolute cap: at most 3 writes per session
        write_positions = sorted(random.sample(range(2, max(3, n_rows - 1)), min(n_writes, n_rows - 2)))
        phases = ["read"] * n_rows
        # Alternate reads and idles for realism
        for k in range(n_rows):
            if random.random() < 0.30:
                phases[k] = "idle"
        # Place isolated writes
        for wp in write_positions:
            if wp < len(phases):
                phases[wp] = "write"
            # Ensure no two writes are adjacent
            if wp > 0 and phases[wp-1] == "write":
                phases[wp-1] = "read"
        # Guarantee at least 3 non-write rows between any two writes
        last_write = -10
        for k in range(len(phases)):
            if phases[k] == "write":
                if k - last_write < 4:
                    phases[k] = "read"
                else:
                    last_write = k

    elif session_type == "attack_phantom":
        # V10 NEW (Failure 2): Zero-write session — pure dwell/monitoring.
        # Attacker reads everything, writes nothing in this session.
        # Label=2 but behaviorally identical to Normal_OPS/REMOTE.
        phases = []
        for _ in range(n_rows):
            phases.append(random.choices(["read", "idle", "browse"], weights=[55, 30, 15])[0])

    elif session_type == "normal_maint":
        phases = (["login"] +
                  ["read"]   * max(1, n_rows // 6) +
                  ["write"]  * max(1, n_rows * 2 // 5) +
                  ["browse"] * max(1, n_rows // 5) +
                  ["read"]   * max(1, n_rows - n_rows*3//5 - 1))
        if n_rows >= 6 and random.random() < 0.25:
            gap_pos = random.randint(2, max(2, n_rows // 2))
            if gap_pos < len(phases):
                phases[gap_pos] = random.choice(["browse", "read"])
    else:  # normal_ops
        phases = (["login"] +
                  ["read"]   * max(1, n_rows * 3 // 5) +
                  ["idle"]   * max(1, n_rows // 5) +
                  ["logout"] * max(1, n_rows - n_rows*4//5 - 1))

    # Pad/trim
    while len(phases) < n_rows: phases.append(phases[-1])
    phases = phases[:n_rows]

    # Normal sessions: inject idle pauses
    if not session_type.startswith("attack") and n_rows >= 5:
        n_idle = random.randint(0, 2)
        for pos in random.sample(range(1, n_rows - 1), min(n_idle, n_rows - 2)):
            phases[pos] = "idle"

    # Stealth attacks: occasional mid-session read-pause
    if session_type.startswith("attack") and n_rows >= 6 and random.random() < 0.20:
        pause_pos = random.randint(n_rows // 3, 2 * n_rows // 3)
        phases[pause_pos] = "read"

    # Post-write verify for camouflage/persist
    if session_type in ("attack_persist", "attack_camouflage", "attack_stealth_maint") and n_rows >= 8:
        if random.random() < 0.35:
            vp = min(n_rows - 1, random.randint(n_rows * 2//3, n_rows - 1))
            phases[vp] = "read"

    # ── Accumulate session state ───────────────────────────────────────────
    write_ops_seen = []
    tags_seen = set()
    service_counts = {}
    state_transitions = 0
    prev_phase = None
    prev_service_name = "Read"
    cumulative_dur = 0
    cumulative_drift = 0.0
    # V11: Track per-session process health trajectory
    cumulative_phd = 0.0    # sum of process_health_delta values this session
    n_writes_seen = 0        # count of write rows seen so far

    for i, phase in enumerate(phases):
        # V9 operator fatigue for normal sessions
        fatigue_factor = 1.0
        if not session_type.startswith("attack") and n_rows >= 10:
            fatigue_factor = 1.0 + (i / n_rows) * 0.40

        drift_factor = 1.0 + drift_direction * drift_magnitude * (i / max(n_rows - 1, 1))

        if phase == "idle" and random.random() < 0.25:
            inter_raw = _lognormal_int(inter_base * 8, 0.8, inter_base * 3, inter_base * 30)
        else:
            inter_raw = max(10, int(inter_base * random.lognormvariate(0, 0.5)))
        inter = max(10, int(inter_raw * drift_factor * fatigue_factor))
        cumulative_dur += inter

        raw_drift = (inter - inter_base) / max(inter_base, 1)
        cumulative_drift += raw_drift
        session_temporal_drift = round(cumulative_drift / max(i + 1, 1), 6)

        is_write = phase in ("write", "persist") or (phase == "exploit" and random.random() < 0.4)
        write_ops_seen.append(int(is_write))
        write_ratio_so_far = sum(write_ops_seen) / max(i + 1, 1)

        new_tags = random.randint(0, 3) if phase in ("browse", "read", "probe") else random.randint(0, 1)
        for _ in range(new_tags):
            tags_seen.add(random.choice(TAG_NAMES))
        n_unique_tags = len(tags_seen)

        svc = phase
        service_counts[svc] = service_counts.get(svc, 0) + 1

        _phase_to_svc = {
            "read": "Read", "write": "Write", "browse": "Browse",
            "idle": "Subscribe", "login": "CreateSession", "logout": "CloseSession",
            "probe": "Browse", "auth": "ActivateSession", "escalate": "Write",
            "persist": "Write", "cleanup": "CloseSession", "exploit": "Write",
        }
        curr_svc_name = _phase_to_svc.get(phase, "Read")
        _trans_rarity = _transition_rarity(prev_service_name, curr_svc_name)
        prev_service_name = curr_svc_name

        total_svcs = sum(service_counts.values())
        entropy = 0.0
        if total_svcs > 1:
            entropy = -sum((c / total_svcs) * math.log2(c / total_svcs)
                          for c in service_counts.values() if c > 0)

        if prev_phase is not None and phase != prev_phase:
            state_transitions += 1
        prev_phase = phase

        req_variance = float(inter_base * random.uniform(0.1, 0.8))
        idle_gap = inter * random.randint(3, 8) if phase == "idle" else max(0, inter // 5)

        arc.append({
            "session_duration_total"        : min(cumulative_dur, total_dur),
            "session_request_variance"      : round(req_variance, 2),
            "session_write_ratio"           : round(write_ratio_so_far, 4),
            "session_unique_tags"           : n_unique_tags,
            "session_behavior_entropy"      : round(entropy, 4),
            "session_event_index"           : i,
            "session_state_transition_count": state_transitions,
            "session_idle_gap_ms"           : idle_gap,
            "session_temporal_drift"        : session_temporal_drift,
            "action_transition_rarity"      : _trans_rarity,
            # V11: process consequence placeholders — filled by _build_*_row
            "_cumulative_phd_so_far"        : round(cumulative_phd, 4),
            "_n_writes_seen"                : n_writes_seen,
        })
    return arc


def _operational_load_score(ctx: dict, mode: str) -> float:
    base = 0.3
    if ctx["is_peak_prod"]:       base += 0.35
    if ctx["is_shift_change"]:    base += 0.10
    if mode in ("BURST", "ALARM_FLOOD", "FAILOVER"): base += 0.25
    if mode == "ALARM_FLOOD" and ctx.get("is_alarm_risk"):  base += 0.08
    if ctx.get("is_historian_sync"):   base += 0.12
    if ctx.get("is_ramp_period"):      base += 0.08
    if ctx.get("is_alarm_risk"):       base += 0.07
    if ctx["is_maintenance"]:          base -= 0.15
    if ctx["is_weekend"]:              base -= 0.10
    if ctx.get("reduced_staffing"):    base -= 0.08
    if ctx.get("is_backup_window"):    base -= 0.05
    return round(min(1.0, max(0.0, base + random.gauss(0, 0.05))), 4)

def _activity_burst_score(rpm: int, mode: str) -> float:
    score = min(1.0, (rpm / 12.0) * random.uniform(0.8, 1.2))
    if mode in ("BURST", "ALARM_FLOOD", "FAILOVER", "HISTORIAN"):
        score = min(1.0, score * 1.5)
    return round(score, 4)


# ─────────────────────────────────────────────────────────────────────────────
#  NORMAL TRAFFIC — preserved from V9 (unchanged)
# ─────────────────────────────────────────────────────────────────────────────

def _build_normal_row(ctx, mode, session_state: dict) -> dict:
    r   = _base_row()
    ts  = _ts_from_context(ctx)
    r["timestamp"] = ts
    op_mode = ctx.get("op_mode", "STEADY_STATE")
    auth, sec_mode, sec_policy, has_cert = _security_posture(legacy_prob=0.12)
    cert_thumb = _rng_cert_thumb() if has_cert else ""

    if mode == "OPS":
        client = random.choice(KNOWN_CLIENT_NAMES); clsid = random.choice(KNOWN_CLSIDS)
        service = random.choices(["Read","Subscribe","Publish","CreateMonitoredItems","Browse"], weights=[40,30,15,10,5], k=1)[0]
        failed_auth=0; login_st="Success"; sess_result="Success"; is_new=0
        seen_cnt=_lognormal_int(200,1.2,20,5000); rpm=_lognormal_int(12,0.8,2,60)
        unique_tags=random.randint(1,15); write_ops=_lognormal_int(3,1.0,0,25)
        duration_ms=_lognormal_int(2500,1.1,200,20000); payload=random.randint(64,1024)
        resp_ms=_lognormal_int(50,0.9,5,300); privilege=random.choice(["Operator","Engineer"])
        tag_q=random.choices(["Good","Uncertain"],weights=[95,5])[0]; status=random.choice(OPC_STATUS_OK)
        geo_mis=0; whitelist=1; username=f"op_user_{random.randint(1,20)}"; access_out=0
        active_sess=_lognormal_int(20,0.9,5,80)

    elif mode == "MAINT":
        client=random.choice(KNOWN_CLIENT_NAMES+CONTRACTOR_CLIENT_NAMES); clsid=random.choice(KNOWN_CLSIDS)
        auth,sec_mode,sec_policy,has_cert=_security_posture(legacy_prob=0.18); cert_thumb=_rng_cert_thumb() if has_cert else ""
        service=random.choices(["Write","Read","Browse","Subscribe","CreateMonitoredItems"],weights=[38,32,18,8,4],k=1)[0]
        failed_auth=0; login_st="Success"; sess_result="Success"; is_new=0
        seen_cnt=_lognormal_int(60,1.0,10,600); rpm=_lognormal_int(15,0.9,2,60)
        unique_tags=random.randint(1,20); write_ops=_lognormal_int(18,1.0,0,80)
        duration_ms=_lognormal_int(4000,1.1,500,30000); payload=random.randint(64,1500)
        resp_ms=_lognormal_int(60,0.9,5,400); privilege=random.choice(["Engineer","Administrator","Operator"])
        tag_q=random.choices(["Good","Uncertain"],weights=[90,10])[0]; status=random.choice(OPC_STATUS_OK+OPC_STATUS_UNCERTAIN)
        geo_mis=0; whitelist=1
        username=random.choice([f"eng_user_{random.randint(1,8)}",f"op_user_{random.randint(1,20)}",
                                 f"contractor_{random.randint(1,5)}",f"maint_tech_{random.randint(1,5)}"])
        access_out=int(ctx["outside_hours"]); active_sess=_lognormal_int(8,0.8,2,30)

    elif mode == "CALIBRATION":
        client=random.choice(KNOWN_CLIENT_NAMES[:6]+CONTRACTOR_CLIENT_NAMES); clsid=random.choice(KNOWN_CLSIDS)
        auth,sec_mode,sec_policy,has_cert=_security_posture(legacy_prob=0.10); cert_thumb=_rng_cert_thumb() if has_cert else ""
        service=random.choices(["Write","Read","Browse","Subscribe"],weights=[45,35,15,5],k=1)[0]
        failed_auth=0; login_st="Success"; sess_result="Success"; is_new=0
        seen_cnt=_lognormal_int(80,1.0,20,500); rpm=_lognormal_int(10,0.8,2,30)
        unique_tags=random.randint(1,8); write_ops=_lognormal_int(12,0.9,2,45)
        duration_ms=_lognormal_int(8000,1.0,2000,40000); payload=random.randint(64,512)
        resp_ms=_lognormal_int(40,0.8,5,200); privilege=random.choice(["Engineer","Administrator"])
        tag_q="Good"; status=random.choice(OPC_STATUS_OK); geo_mis=0; whitelist=1
        username=random.choice([f"calibration_tech_{random.randint(1,3)}",
                                 f"eng_user_{random.randint(1,8)}",f"process_eng_{random.randint(1,3)}"])
        access_out=int(ctx["outside_hours"]) if random.random()<0.60 else 0; active_sess=_lognormal_int(5,0.7,1,20)

    elif mode == "MISTAKE":
        client=random.choice(KNOWN_CLIENT_NAMES); clsid=random.choice(KNOWN_CLSIDS)
        service=random.choices(["Write","Browse","Read","Subscribe"],weights=[40,25,25,10],k=1)[0]
        failed_auth=random.randint(0,3); login_st=random.choice(["Success","Failure"])
        sess_result="Success" if login_st=="Success" else random.choice(["Failed","Success"]); is_new=0
        seen_cnt=_lognormal_int(50,1.1,5,500); rpm=_lognormal_int(25,1.0,3,80)
        unique_tags=random.randint(1,25); write_ops=_lognormal_int(30,1.1,1,120)
        duration_ms=_lognormal_int(1500,1.0,100,15000); payload=random.randint(64,2048)
        resp_ms=_lognormal_int(80,1.0,5,600); privilege=random.choice(["Operator","Engineer","Administrator"])
        tag_q=random.choices(["Good","Uncertain"],weights=[80,20])[0]; status=random.choice(OPC_STATUS_OK+OPC_STATUS_UNCERTAIN)
        geo_mis=0; whitelist=1; username=f"op_user_{random.randint(1,20)}"; access_out=0; active_sess=_lognormal_int(15,0.9,4,60)

    elif mode == "BURST":
        client=random.choice(KNOWN_CLIENT_NAMES); clsid=random.choice(KNOWN_CLSIDS)
        service=random.choices(["Read","Subscribe","Publish","CreateMonitoredItems"],weights=[40,30,20,10],k=1)[0]
        failed_auth=0; login_st="Success"; sess_result="Success"; is_new=0
        seen_cnt=_lognormal_int(150,1.0,20,1000); rpm=_lognormal_int(55,1.0,15,200)
        unique_tags=random.randint(5,40); write_ops=_lognormal_int(5,0.9,0,30)
        duration_ms=_lognormal_int(2000,1.0,200,15000); payload=random.randint(128,2048)
        resp_ms=_lognormal_int(70,0.9,5,400); privilege=random.choice(["Operator","Engineer"])
        tag_q=random.choices(["Good","Uncertain"],weights=[92,8])[0]; status=random.choice(OPC_STATUS_OK)
        geo_mis=0; whitelist=1; username=f"op_user_{random.randint(1,20)}"; access_out=0; active_sess=_lognormal_int(30,0.9,10,100)

    elif mode == "REMOTE":
        op=_pick_remote_operator(); client=random.choice(KNOWN_CLIENT_NAMES+CONTRACTOR_CLIENT_NAMES); clsid=random.choice(KNOWN_CLSIDS)
        auth=op["auth"]; sec_mode=random.choice(["Sign","SignAndEncrypt"]); sec_policy=random.choice(["Basic256","Basic256Sha256"])
        has_cert=(auth=="Certificate"); cert_thumb=_rng_cert_thumb() if has_cert else ""
        service=random.choices(["Read","Browse","Subscribe","Write","CreateMonitoredItems"],weights=[40,25,20,10,5],k=1)[0]
        failed_auth=0; login_st="Success"; sess_result="Success"; is_new=0
        seen_cnt=op["seen_baseline"]+random.randint(-30,80); rpm=_lognormal_int(10,0.9,2,40)
        unique_tags=random.randint(2,20); write_ops=_lognormal_int(4,0.8,0,20)
        duration_ms=_lognormal_int(5000,1.1,500,35000); payload=random.randint(128,2048)
        resp_ms=_lognormal_int(120,1.0,20,800); privilege=op["privilege"]
        tag_q=random.choices(["Good","Uncertain"],weights=[90,10])[0]; status=random.choice(OPC_STATUS_OK)
        geo_mis=int(random.random()<0.15); whitelist=1; username=op["username"]
        access_out=int(ctx["outside_hours"]) if random.random()<0.6 else 0; active_sess=_lognormal_int(12,0.8,3,45)

    elif mode == "HISTORIAN":
        client=random.choice(["HIST.BatchRecord_001","Ignition_SCADA","AspenTech_HMI"]); clsid=random.choice(KNOWN_CLSIDS)
        service=random.choices(["Read","Subscribe","Publish","Browse"],weights=[50,25,20,5],k=1)[0]
        failed_auth=0; login_st="Success"; sess_result="Success"; is_new=0
        seen_cnt=_lognormal_int(800,1.0,100,3000); rpm=_lognormal_int(40,0.9,10,150)
        unique_tags=random.randint(10,50); write_ops=_lognormal_int(2,0.8,0,10)
        duration_ms=_lognormal_int(8000,1.0,2000,40000); payload=random.randint(256,8192)
        resp_ms=_lognormal_int(80,0.9,10,400); privilege=random.choice(["Operator","ReadOnly"])
        tag_q="Good"; status=random.choice(OPC_STATUS_OK); geo_mis=0; whitelist=1
        username=f"historian_svc_{random.randint(1,3)}"; access_out=int(ctx.get("is_historian_sync",False)); active_sess=_lognormal_int(25,0.9,8,80)

    elif mode == "FAILOVER":
        client=random.choice(KNOWN_CLIENT_NAMES); clsid=random.choice(KNOWN_CLSIDS)
        service=random.choices(["Read","Write","CreateSession","ActivateSession","Subscribe"],weights=[30,25,20,15,10],k=1)[0]
        failed_auth=random.randint(0,2); login_st="Success"; sess_result="Success"; is_new=0
        seen_cnt=_lognormal_int(120,0.9,20,600); rpm=_lognormal_int(35,1.0,5,120)
        unique_tags=random.randint(5,35); write_ops=_lognormal_int(20,1.0,2,80)
        duration_ms=_lognormal_int(6000,1.1,1000,40000); payload=random.randint(128,4096)
        resp_ms=_lognormal_int(150,1.1,10,1200); privilege=random.choice(["Engineer","Administrator"])
        tag_q=random.choices(["Good","Uncertain","Bad"],weights=[70,20,10])[0]; status=random.choice(OPC_STATUS_OK+OPC_STATUS_UNCERTAIN)
        geo_mis=0; whitelist=1; username=f"eng_user_{random.randint(1,8)}"
        access_out=int(ctx["outside_hours"]) if random.random()<0.5 else 0; active_sess=_lognormal_int(40,1.0,10,120)

    elif mode == "ALARM_FLOOD":
        client=random.choice(KNOWN_CLIENT_NAMES); clsid=random.choice(KNOWN_CLSIDS)
        service=random.choices(["Read","Subscribe","Publish","CreateMonitoredItems","Write"],weights=[35,30,20,10,5],k=1)[0]
        failed_auth=0; login_st="Success"; sess_result="Success"; is_new=0
        seen_cnt=_lognormal_int(300,1.0,50,1500); rpm=_lognormal_int(80,1.0,20,300)
        unique_tags=random.randint(10,60); write_ops=_lognormal_int(8,0.9,0,40)
        duration_ms=_lognormal_int(3000,1.0,300,20000); payload=random.randint(256,4096)
        resp_ms=_lognormal_int(100,1.0,10,800); privilege=random.choice(["Operator","Engineer"])
        tag_q=random.choices(["Good","Uncertain"],weights=[80,20])[0]; status=random.choice(OPC_STATUS_OK+OPC_STATUS_UNCERTAIN)
        geo_mis=0; whitelist=1; username=f"op_user_{random.randint(1,20)}"; access_out=0; active_sess=_lognormal_int(35,1.0,15,100)

    else:  # RECOVERY
        client=random.choice(KNOWN_CLIENT_NAMES+CONTRACTOR_CLIENT_NAMES); clsid=random.choice(KNOWN_CLSIDS)
        auth,sec_mode,sec_policy,has_cert=_security_posture(legacy_prob=0.10); cert_thumb=_rng_cert_thumb() if has_cert else ""
        service=random.choices(["Write","Read","Browse","Subscribe"],weights=[45,30,15,10],k=1)[0]
        _phase_high=random.random()<0.50
        write_ops=_lognormal_int(40,0.9,15,100) if _phase_high else random.randint(0,4)
        rpm=_lognormal_int(35,1.0,8,100) if _phase_high else _lognormal_int(8,0.8,2,20)
        failed_auth=0; login_st="Success"; sess_result="Success"; is_new=0
        seen_cnt=_lognormal_int(100,0.9,20,500); unique_tags=random.randint(3,20)
        duration_ms=_lognormal_int(4000,1.0,500,20000); payload=random.randint(128,2048); resp_ms=_lognormal_int(80,0.9,10,500)
        privilege=random.choice(["Engineer","Administrator","Operator"])
        tag_q=random.choices(["Good","Uncertain"],weights=[70,30])[0]; status=random.choice(OPC_STATUS_OK+OPC_STATUS_UNCERTAIN)
        geo_mis=0; whitelist=1
        username=random.choice([f"eng_user_{random.randint(1,8)}",f"op_user_{random.randint(1,20)}"])
        access_out=int(ctx["outside_hours"]) if random.random()<0.10 else 0; active_sess=_lognormal_int(12,0.8,3,40)

    load_score  = _operational_load_score(ctx, mode)
    burst_score = _activity_burst_score(rpm, mode)
    inter_arr   = _lognormal_int(800, 1.0, 50, 10000)
    tag = random.choice(CALIBRATION_TAGS) if mode == "CALIBRATION" else random.choice(TAG_NAMES)
    dtype = random.choice(TAG_DATA_TYPES)
    sev   = 0.05 + 0.15 * (write_ops / max(write_ops + 1, 1))
    bv, av, delta, pct, legality, phd = _rng_tag_value_semantic(tag, dtype, sev, "none", op_mode)
    if sev < 0.20 and pct > 0 and dtype in ("Float", "Double"):
        pct = round(max(0.0, pct + random.gauss(0, 0.3) * pct), 2)

    # V11: compute session process convergence from arc state
    _cum_phd = session_state.pop("_cumulative_phd_so_far", 0.0)
    _n_w = session_state.pop("_n_writes_seen", 0)
    # Maintenance, Calibration, Recovery: phd must be positive (corrective intent)
    if mode in ("MAINT", "CALIBRATION", "RECOVERY"):
        phd = round(max(0.0, min(1.0, abs(phd) * random.uniform(0.85, 1.20))), 4)
    _new_cum = _cum_phd + phd
    _is_write_row = service in ("Write",) or mode in ("MAINT", "CALIBRATION", "FAILOVER", "RECOVERY", "MISTAKE")
    _new_n_w = _n_w + (1 if _is_write_row else 0)
    # session_process_convergence: rolling mean of phd — maintenance stays positive
    sess_proc_conv = round(_new_cum / max(_new_n_w + 1, 1), 4)
    # cumulative_process_deviation: signed running sum — maintenance positive, attacks negative
    cum_dev = round(_new_cum, 4)

    r.update({
        "src_ip": _rng_ip(private=(geo_mis == 0 or random.random() < 0.7)),
        "dst_ip": _rng_ip(private=True), "src_port": _rng_port(high_range=True), "dst_port": 4840,
        "connection_duration_ms": duration_ms, "opc_client_name": client,
        "opc_client_clsid": clsid, "opc_server_endpoint_url": _endpoint(),
        "client_certificate_thumbprint": cert_thumb, "authentication_method": auth,
        "security_mode": sec_mode, "security_policy": sec_policy, "opc_service_type": service,
        "opc_status_code": status, "response_time_ms": resp_ms, "payload_size_bytes": payload,
        "tag_name": tag, "tag_data_type": dtype, "tag_value_before": bv, "tag_value_after": av,
        "tag_quality": tag_q, "tag_access_rights": random.choice(["Read","ReadWrite"]),
        "value_change_delta": delta, "value_change_percent": pct,
        "username": username, "login_status": login_st, "failed_auth_count": failed_auth,
        "privilege_level": privilege, "session_activation_result": sess_result,
        "is_new_client": is_new, "client_first_seen_timestamp": ts, "client_seen_count": seen_cnt,
        "requests_per_minute": rpm, "unique_tags_accessed": unique_tags, "write_ops_in_window": write_ops,
        "access_outside_business_hours": access_out, "geo_location_mismatch": geo_mis,
        "client_known_to_whitelist": whitelist, "hour_of_day": ctx["hour"],
        "shift_id": ctx["shift_id"], "business_hours": int(ctx["is_business_hours"]),
        "maintenance_window": int(ctx["is_maintenance"]), "is_weekend": int(ctx["is_weekend"]),
        "activity_burst_score": burst_score, "session_interarrival_ms": inter_arr,
        "operational_load_score": load_score, **session_state,
        "value_semantic_legality": legality, "attack_chain_phase": "",
        "process_health_delta": phd, "session_process_convergence": sess_proc_conv,
        "cumulative_process_deviation": cum_dev,
        "label": 0, "label_str": "Normal", "behavioral_profile": f"Normal_{mode}",
    })
    r = _inject_env_chaos(r, ctx, class_label=0)
    return r


def generate_normal_session() -> list:
    ctx = _temporal_context()
    mode = random.choices(
        ["OPS","MAINT","CALIBRATION","MISTAKE","BURST","REMOTE","HISTORIAN","FAILOVER","ALARM_FLOOD","RECOVERY"],
        weights=[33,10,7,8,9,7,6,6,7,7], k=1
    )[0]
    if mode == "MAINT" and not ctx["is_maintenance"]:
        if random.random() < 0.7: ctx["is_maintenance"]=True; ctx["outside_hours"]=True
    if mode == "MAINT" and ctx["shift_id"] != 2 and random.random() < 0.40:
        ctx.update({"shift_id":2,"reduced_staffing":True,"is_maintenance":True,"outside_hours":True,"op_mode":"MAINTENANCE_MODE"})
        ctx["hour"] = random.choice(list(range(0,6))+[22,23])
    if mode == "CALIBRATION" and random.random() < 0.65:
        ctx.update({"is_maintenance":True,"outside_hours":True,"op_mode":"MAINTENANCE_MODE"})
        ctx["hour"] = random.choice(list(range(1,6))+[22,23])
    if mode == "REMOTE": ctx["outside_hours"] = random.random() < 0.6

    if mode == "FAILOVER": n_rows=random.randint(5,30); session_type="normal_ops"
    elif mode in ("ALARM_FLOOD","BURST"): n_rows=random.randint(4,20); session_type="normal_ops"
    elif mode in ("MAINT","CALIBRATION"): n_rows=random.randint(4,20); session_type="normal_maint"
    elif mode == "RECOVERY": n_rows=random.randint(4,16); session_type="normal_maint"
    else: n_rows=random.randint(2,12); session_type="normal_ops"

    arc = _make_session_arc(n_rows, session_type, ctx=ctx)
    return [_build_normal_row(ctx, mode, arc[i]) for i in range(n_rows)]


# ─────────────────────────────────────────────────────────────────────────────
#  UNAUTHORIZED ACCESS  (unchanged from V9)
# ─────────────────────────────────────────────────────────────────────────────

def _build_unauth_row(ctx, profile, session_state: dict) -> dict:
    r = _base_row(); ts = _ts_from_context(ctx); r["timestamp"] = ts
    if profile == "OBVIOUS":
        client=random.choice(UNKNOWN_CLIENT_NAMES); clsid=random.choice(UNKNOWN_CLSIDS)
        has_cert=random.random()<0.1; auth="Anonymous"; sec_mode="None"; sec_policy="None"
        service=random.choices(["CreateSession","ActivateSession","Read"],weights=[50,35,15],k=1)[0]
        failed_auth=random.randint(12,50); login_st=random.choices(["Failure","Failure","Locked"],weights=[50,40,10])[0]
        sess_result="Failed"; rpm=_lognormal_int(120,0.8,40,400); unique_tags=random.randint(0,4); write_ops=0
        duration_ms=random.randint(10,600); payload=random.randint(32,200); resp_ms=random.randint(5,100)
        privilege="Guest"; whitelist=0; is_new=1; seen_cnt=random.randint(1,8)
        geo_mis=int(random.random()<0.65); access_out=int(ctx["outside_hours"]) if random.random()<0.7 else 0
        status=random.choice(OPC_STATUS_BAD[:3]); username=random.choice(["root","admin","administrator","guest","service"])
        tag_q=random.choice(["Bad","Uncertain"]); active_sess=_lognormal_int(20,0.9,5,80)
    elif profile == "MODERATE":
        known_client=random.random()<0.40
        client=random.choice(KNOWN_CLIENT_NAMES if known_client else UNKNOWN_CLIENT_NAMES)
        clsid=random.choice(KNOWN_CLSIDS if known_client else UNKNOWN_CLSIDS)
        has_cert=random.random()<0.35; auth=random.choice(["Username","Username","Anonymous"])
        sec_mode=random.choice(["Sign","None"]); sec_policy="Basic128Rsa15" if sec_mode=="Sign" else "None"
        service=random.choices(["CreateSession","ActivateSession","Read","Browse"],weights=[30,30,25,15],k=1)[0]
        failed_auth=random.randint(3,20); login_st=random.choices(["Failure","Failure","Success"],weights=[55,30,15])[0]
        sess_result=random.choices(["Failed","Failed","Success"],weights=[60,25,15])[0]
        rpm=_lognormal_int(55,1.0,15,180); unique_tags=random.randint(0,10); write_ops=random.randint(0,5)
        duration_ms=_lognormal_int(400,1.1,20,4000); payload=random.randint(50,512); resp_ms=_lognormal_int(80,0.9,5,400)
        privilege=random.choice(["Guest","ReadOnly","Operator"]); whitelist=int(known_client); is_new=int(random.random()<0.6)
        seen_cnt=random.randint(1,20); geo_mis=int(random.random()<0.40)
        access_out=int(ctx["outside_hours"]) if random.random()<0.55 else 0
        status=random.choice(OPC_STATUS_BAD+OPC_STATUS_UNCERTAIN)
        username=random.choice([f"op_user_{random.randint(1,20)}","admin","service_acct",f"user_{random.randint(100,999)}","backup_svc"])
        tag_q=random.choices(["Good","Bad","Uncertain"],weights=[30,40,30])[0]; active_sess=_lognormal_int(25,0.9,8,80)
    else:  # STEALTHY
        op=_pick_remote_operator() if random.random()<0.55 else None
        known_client=random.random()<0.75
        client=random.choice(KNOWN_CLIENT_NAMES+CONTRACTOR_CLIENT_NAMES if known_client else UNKNOWN_CLIENT_NAMES)
        clsid=random.choice(KNOWN_CLSIDS if known_client else UNKNOWN_CLSIDS)
        has_cert=random.random()<0.70
        if op: auth=op["auth"]; username=op["username"]; seen_cnt=op["seen_baseline"]+random.randint(-50,50); privilege=op["privilege"]
        else:
            auth=random.choice(["Username","Certificate"])
            username=random.choice([f"op_user_{random.randint(1,20)}",f"eng_user_{random.randint(1,8)}","backup_svc",f"vendor_{random.randint(1,5)}"])
            seen_cnt=random.randint(5,80); privilege=random.choice(["ReadOnly","Operator","Guest"])
        sec_mode=random.choice(["Sign","Sign","SignAndEncrypt"]); sec_policy=random.choice(["Basic256","Basic256Sha256"])
        service=random.choices(["Read","Browse","CreateSession","Subscribe"],weights=[40,30,20,10],k=1)[0]
        failed_auth=random.randint(0,6); login_st=random.choices(["Failure","Success","Success"],weights=[25,50,25],k=1)[0]
        sess_result="Success"; rpm=_lognormal_int(15,0.9,2,50); unique_tags=random.randint(1,12); write_ops=random.randint(0,2)
        duration_ms=_lognormal_int(2000,1.1,300,12000); payload=random.randint(100,1024); resp_ms=_lognormal_int(80,0.9,15,500)
        whitelist=int(known_client); is_new=int(random.random()<0.25); geo_mis=int(random.random()<0.20)
        access_out=int(ctx["is_maintenance"]) if random.random()<0.4 else 0
        status=random.choice(OPC_STATUS_OK+OPC_STATUS_BAD+OPC_STATUS_UNCERTAIN)
        tag_q=random.choices(["Good","Uncertain","Bad"],weights=[55,30,15])[0]; active_sess=_lognormal_int(10,0.9,3,40)

    cert_thumb=_rng_cert_thumb() if has_cert else ""; dtype=random.choice(TAG_DATA_TYPES); tag=random.choice(TAG_NAMES)
    bv,av,delta,pct=_rng_tag_value(dtype,severity=0.0)
    load_score=_operational_load_score(ctx,"ATTACK"); burst_score=_activity_burst_score(rpm,"ATTACK")
    inter_arr=_lognormal_int(500,1.0,30,8000); legality=round(random.gauss(0.80,0.15),4)
    r.update({
        "src_ip":_rng_ip(private=(random.random()<0.5)),"dst_ip":_rng_ip(private=True),
        "src_port":_rng_port(high_range=True),"dst_port":random.choice([4840,4843]),
        "connection_duration_ms":duration_ms,"opc_client_name":client,"opc_client_clsid":clsid,
        "opc_server_endpoint_url":_endpoint(),"client_certificate_thumbprint":cert_thumb,
        "authentication_method":auth,"security_mode":sec_mode,"security_policy":sec_policy,
        "opc_service_type":service,"opc_status_code":status,"response_time_ms":resp_ms,
        "payload_size_bytes":payload,"tag_name":tag,"tag_data_type":dtype,"tag_value_before":bv,
        "tag_value_after":av,"tag_quality":tag_q,"tag_access_rights":random.choice(["Read","ReadWrite"]),
        "value_change_delta":delta,"value_change_percent":pct,"username":username,
        "login_status":login_st,"failed_auth_count":failed_auth,"privilege_level":privilege,
        "session_activation_result":sess_result,"is_new_client":is_new,"client_first_seen_timestamp":ts,
        "client_seen_count":seen_cnt,"requests_per_minute":rpm,"unique_tags_accessed":unique_tags,
        "write_ops_in_window":write_ops,"access_outside_business_hours":access_out,
        "geo_location_mismatch":geo_mis,"client_known_to_whitelist":whitelist,
        "hour_of_day":ctx["hour"],"shift_id":ctx["shift_id"],"business_hours":int(ctx["is_business_hours"]),
        "maintenance_window":int(ctx["is_maintenance"]),"is_weekend":int(ctx["is_weekend"]),
        "activity_burst_score":burst_score,"session_interarrival_ms":inter_arr,
        "operational_load_score":load_score,**session_state,
        "value_semantic_legality":max(0.0,min(1.0,legality)),
        "process_health_delta":0.0,"session_process_convergence":0.0,
        "cumulative_process_deviation":0.0,
        "label":1,"label_str":"Unauthorized Access","behavioral_profile":f"UnauthorizedAccess_{profile}",
    })
    r=_inject_env_chaos(r,ctx,class_label=1); return r

def generate_unauthorized_session() -> list:
    ctx=_temporal_context()
    profile=random.choices(["OBVIOUS","MODERATE","STEALTHY"],weights=[22,43,35],k=1)[0]
    if profile=="STEALTHY": ctx=_stealth_temporal_context()
    if profile=="OBVIOUS": n_rows=random.randint(2,8); session_type="attack_probe"
    elif profile=="MODERATE": n_rows=random.randint(3,15); session_type="attack_probe"
    else: n_rows=random.randint(4,25); session_type="attack_recon"
    arc=_make_session_arc(n_rows,session_type,ctx=ctx)
    return [_build_unauth_row(ctx,profile,arc[i]) for i in range(n_rows)]


# ─────────────────────────────────────────────────────────────────────────────
#  TAG MODIFICATION — V10: 7 profiles (complete stealth overhaul)
#
#  V10 DESIGN PHILOSOPHY:
#  The 4 stealth profiles (GRADUAL, STEALTHY, CAMOUFLAGE, MAINT_BLEND) now share
#  parameters from Normal_MAINT/CALIBRATION distributions exactly. The only
#  observable differences are:
#    - Directional process drift (within safe_delta — individually invisible)
#    - Session membership (impossible to detect per-row)
#  The IDS must learn BEHAVIORAL NARRATIVES, not row-level statistics.
# ─────────────────────────────────────────────────────────────────────────────

def _build_tagmod_row(ctx, profile, session_state: dict, severity: float,
                      session_meta: dict = None) -> dict:
    """
    V10: Stealth profiles (GRADUAL, STEALTHY, CAMOUFLAGE, MAINT_BLEND, ULTRA_SLOW)
    draw all observable statistics from Normal distributions.
    The IDS cannot detect them from single-row statistics alone.
    """
    r  = _base_row()
    ts = _ts_from_context(ctx)
    r["timestamp"] = ts
    op_mode = ctx.get("op_mode", "STEADY_STATE")
    session_meta = session_meta or {}
    drift_sign = session_meta.get("drift_sign", random.choice([-1, 1]))

    # ── OBVIOUS (unchanged — provides clear positive signal for IDS) ──────
    if profile == "OBVIOUS":
        known=False; client=random.choice(UNKNOWN_CLIENT_NAMES); clsid=random.choice(UNKNOWN_CLSIDS)
        has_cert=random.random()<0.10; auth="Anonymous"; sec_mode="None"; sec_pol="None"
        service=random.choices(["Write","Write","Write","Read"],weights=[65,15,10,10],k=1)[0]
        tag=random.choice(CRITICAL_TAGS) if random.random()<0.32 else random.choice(TAG_NAMES)
        write_ops=random.randint(30,160); rpm=_lognormal_int(80,0.9,20,260); unique=random.randint(1,6)
        duration=_lognormal_int(800,1.0,100,8000); payload=random.randint(256,4096); resp_ms=random.randint(5,200)
        failed_auth=random.randint(0,3); login_st="Success"; sess_res="Success"
        privilege=random.choice(["Engineer","Administrator"]); whitelist=0; is_new=1; seen_cnt=random.randint(1,15)
        geo_mis=0; access_out=int(ctx["outside_hours"]) if random.random()<0.6 else 0
        status=random.choice(OPC_STATUS_OK); username=random.choice(["auto_script","plc_service","maintenance_acct"])
        tag_q="Good"; active_sess=_lognormal_int(15,0.9,3,60)
        _attack_mode="obvious"

    # ── MODERATE ──────────────────────────────────────────────────────────
    elif profile == "MODERATE":
        known=random.random()<0.55
        client=random.choice(KNOWN_CLIENT_NAMES if known else UNKNOWN_CLIENT_NAMES)
        clsid=random.choice(KNOWN_CLSIDS if known else UNKNOWN_CLSIDS)
        has_cert=known and random.random()<0.65
        auth="Username" if known else random.choice(["Anonymous","Username"])
        sec_mode=random.choice(["Sign","None"]) if not known else "Sign"
        sec_pol="Basic256" if sec_mode=="Sign" else "None"
        _norm_phase=random.random()<0.12
        if _norm_phase: service=random.choices(["Read","Browse","Subscribe"],weights=[50,30,20],k=1)[0]
        else: service=random.choices(["Write","Read","Subscribe","Browse"],weights=[38,30,17,15],k=1)[0]
        tag=random.choice(CRITICAL_TAGS if random.random()<0.38 else TAG_NAMES)
        _zone=random.random()
        if _zone<0.15: write_ops=random.randint(0,5)
        elif _zone<0.65: write_ops=random.randint(6,35)
        else: write_ops=random.randint(35,90)
        rpm=_lognormal_int(40,1.0,10,155); unique=random.randint(2,15)
        duration=_lognormal_int(2000,1.1,200,15000); payload=random.randint(128,2048); resp_ms=_lognormal_int(80,1.0,10,500)
        failed_auth=random.randint(0,4); login_st="Success" if failed_auth<3 else random.choice(["Success","Failure"]); sess_res="Success"
        privilege=random.choice(["Engineer","Administrator","Operator"])
        whitelist=int(known); is_new=int(not known and random.random()<0.5)
        seen_cnt=random.randint(5,100) if known else random.randint(1,30)
        geo_mis=int(random.random()<0.15); access_out=int(ctx["outside_hours"]) if random.random()<0.45 else 0
        status=random.choice(OPC_STATUS_OK+OPC_STATUS_BAD[:2])
        username=f"eng_user_{random.randint(1,5)}" if known else random.choice(["maintenance_acct","auto_script","plc_service"])
        tag_q=random.choices(["Good","Uncertain"],weights=[80,20])[0]; active_sess=_lognormal_int(18,0.9,5,65)
        _attack_mode="moderate"

    # ── STEALTHY — V10: drawn from Normal_MAINT distribution ─────────────
    elif profile == "STEALTHY":
        # V10 Failure 1 fix: all observable stats match Normal_MAINT exactly
        client=random.choice(KNOWN_CLIENT_NAMES+CONTRACTOR_CLIENT_NAMES); clsid=random.choice(KNOWN_CLSIDS)
        has_cert=random.random()<0.80
        auth,sec_mode,sec_pol,_=_security_posture(legacy_prob=0.12)  # same as MAINT
        # Service: same weights as Normal_MAINT
        service=random.choices(["Write","Read","Browse","Subscribe","CreateMonitoredItems"],weights=[38,32,18,8,4],k=1)[0]
        tag=random.choice(CALIBRATION_TAGS)  # focused on calibration tags
        # V10 Failure 8 fix: write_ops from Normal_MAINT distribution
        write_ops=_lognormal_int(18,1.0,0,80)
        # V10 Failure 7: human inconsistency — abandoned write (8% chance)
        if random.random()<0.08: write_ops=0
        # V10 Failure 7: duplicate write (5% chance — same as last known value)
        rpm=_lognormal_int(15,0.9,2,60)  # identical to Normal_MAINT
        unique=random.randint(1,20); duration=_lognormal_int(4000,1.1,500,30000)
        payload=random.randint(64,1500); resp_ms=_lognormal_int(60,0.9,5,400)
        failed_auth=0; login_st="Success"; sess_res="Success"
        privilege=random.choice(["Engineer","Administrator","Operator"])  # same as MAINT
        # V10 Failure 1: active_sessions matches Normal_MAINT (was too low)
        active_sess=_lognormal_int(8,0.8,2,30)
        whitelist=1; is_new=0; seen_cnt=_lognormal_int(60,1.0,10,600)  # same as MAINT
        if random.random()<0.05: whitelist=0
        geo_mis=0
        # V10 Failure 3: maintenance window 70% of time
        access_out=(1 if ctx.get("is_maintenance",False) and random.random()<0.70
                    else int(ctx["outside_hours"]) if random.random()<0.30 else 0)
        status=random.choice(OPC_STATUS_OK+OPC_STATUS_UNCERTAIN)
        username=random.choice([f"eng_user_{random.randint(1,8)}",f"op_user_{random.randint(1,20)}",
                                  f"contractor_{random.randint(1,5)}",f"maint_tech_{random.randint(1,5)}"])
        tag_q=random.choices(["Good","Uncertain"],weights=[90,10])[0]  # same as MAINT
        # V10 Failure 4: use coherent_drift for process-valid sabotage
        _attack_mode="coherent_drift"

    # ── GRADUAL — V10: exact MAINT parameters + directional drift ─────────
    elif profile == "GRADUAL":
        # V10: Fully absorbed into MAINT statistical distribution
        # Only detectable via long-horizon drift analysis across sessions
        op=_pick_remote_operator()
        client=random.choice(KNOWN_CLIENT_NAMES+CONTRACTOR_CLIENT_NAMES); clsid=random.choice(KNOWN_CLSIDS)
        has_cert=random.random()<0.82
        auth,sec_mode,sec_pol,_=_security_posture(legacy_prob=0.07)
        service=random.choices(["Write","Read","Browse","Subscribe","CreateMonitoredItems"],weights=[38,32,18,8,4],k=1)[0]
        tag=random.choice(CALIBRATION_TAGS)
        write_ops=_lognormal_int(18,1.0,0,80)  # exact Normal_MAINT distribution
        if random.random()<0.08: write_ops=0   # abandoned write
        rpm=_lognormal_int(15,0.9,2,60)         # exact Normal_MAINT
        unique=random.randint(1,20); duration=_lognormal_int(4000,1.1,500,30000)
        payload=random.randint(64,1500); resp_ms=_lognormal_int(60,0.9,5,400)
        failed_auth=0; login_st="Success"; sess_res="Success"
        privilege=random.choice(["Engineer","Administrator","Operator"])
        active_sess=_lognormal_int(8,0.8,2,30)
        whitelist=1; is_new=0; seen_cnt=_lognormal_int(60,1.0,10,600)
        if random.random()<0.05: whitelist=0
        geo_mis=0
        access_out=(1 if ctx.get("is_maintenance",False) and random.random()<0.70
                    else int(ctx["outside_hours"]) if random.random()<0.30 else 0)
        status=random.choice(OPC_STATUS_OK)
        username=random.choice([f"eng_user_{random.randint(1,8)}",f"op_user_{random.randint(1,20)}",
                                  f"calibration_tech_{random.randint(1,3)}",
                                  f"maint_tech_{random.randint(1,5)}"])
        tag_q="Good"; _attack_mode="coherent_drift"

    # ── CAMOUFLAGE — V10: indistinguishable from Normal_CALIBRATION ───────
    elif profile == "CAMOUFLAGE":
        op=_pick_remote_operator()
        client=random.choice(KNOWN_CLIENT_NAMES[:6]+CONTRACTOR_CLIENT_NAMES); clsid=random.choice(KNOWN_CLSIDS)
        has_cert=random.random()<0.85
        auth,sec_mode,sec_pol,_=_security_posture(legacy_prob=0.08)
        # Service: identical to Normal_CALIBRATION
        service=random.choices(["Write","Read","Browse","Subscribe"],weights=[45,35,15,5],k=1)[0]
        tag=random.choice(CALIBRATION_TAGS)
        # V10: write_ops drawn from Normal_CALIBRATION distribution exactly
        write_ops=_lognormal_int(12,0.9,2,45)
        if random.random()<0.08: write_ops=0   # human abandoned write
        rpm=_lognormal_int(10,0.8,2,30)         # identical to Normal_CALIBRATION
        unique=random.randint(1,8); duration=_lognormal_int(8000,1.0,2000,40000)
        payload=random.randint(64,512); resp_ms=_lognormal_int(40,0.8,5,200)
        failed_auth=0; login_st="Success"; sess_res="Success"
        privilege=random.choice(["Engineer","Administrator"])
        # V10: active_sessions matches Normal_CALIBRATION (was too low)
        active_sess=_lognormal_int(5,0.7,1,20)
        whitelist=1; is_new=0; seen_cnt=_lognormal_int(80,1.0,20,500)  # same as CALIBRATION
        if random.random()<0.03: whitelist=0
        geo_mis=0
        # V10: maintenance_window=1 ALWAYS for CAMOUFLAGE (was 65%)
        ctx["is_maintenance"]=True; ctx["outside_hours"]=True
        access_out=int(ctx["outside_hours"]) if random.random()<0.65 else 0
        status=random.choice(OPC_STATUS_OK)
        username=random.choice([op["username"],f"calibration_tech_{random.randint(1,3)}",
                                  f"eng_user_{random.randint(1,8)}",f"process_eng_{random.randint(1,3)}"])
        tag_q="Good"; _attack_mode="camouflage"

    # ── MAINT_BLEND — V10 NEW (Failure 3): Indistinguishable from MAINT ──
    elif profile == "MAINT_BLEND":
        # EVERY observable parameter drawn directly from Normal_MAINT distribution.
        # The only difference from Normal_MAINT is:
        #   - Uses calibration tags only (focused scope)
        #   - Drift direction is consistent within session (process drift)
        #   - label = 2
        # This is the HARDEST profile — designed to produce inevitable confusion.
        op=_pick_remote_operator()
        client=random.choice(KNOWN_CLIENT_NAMES+CONTRACTOR_CLIENT_NAMES); clsid=random.choice(KNOWN_CLSIDS)
        has_cert=random.random()<0.80
        auth,sec_mode,sec_pol,_=_security_posture(legacy_prob=0.18)  # exact MAINT
        service=random.choices(["Write","Read","Browse","Subscribe","CreateMonitoredItems"],weights=[38,32,18,8,4],k=1)[0]
        tag=random.choice(CALIBRATION_TAGS)  # only difference: focused tags
        # write_ops: EXACT Normal_MAINT lognormal distribution
        write_ops=_lognormal_int(18,1.0,0,80)
        if random.random()<0.08: write_ops=0   # operator abandoned write (human chaos)
        rpm=_lognormal_int(15,0.9,2,60)         # exact Normal_MAINT
        unique=random.randint(1,20); duration=_lognormal_int(4000,1.1,500,30000)
        payload=random.randint(64,1500); resp_ms=_lognormal_int(60,0.9,5,400)
        failed_auth=0; login_st="Success"; sess_res="Success"
        privilege=random.choice(["Engineer","Administrator","Operator"])  # exact MAINT
        active_sess=_lognormal_int(8,0.8,2,30)  # exact MAINT
        whitelist=1; is_new=0; seen_cnt=_lognormal_int(60,1.0,10,600)  # exact MAINT
        geo_mis=0
        access_out=int(ctx["outside_hours"])  # exact MAINT behavior
        status=random.choice(OPC_STATUS_OK+OPC_STATUS_UNCERTAIN)  # exact MAINT
        username=random.choice([f"eng_user_{random.randint(1,8)}",f"op_user_{random.randint(1,20)}",
                                  f"contractor_{random.randint(1,5)}",f"maint_tech_{random.randint(1,5)}"])
        tag_q=random.choices(["Good","Uncertain"],weights=[90,10])[0]  # exact MAINT
        # V11: Use coherent_drift (not camouflage) — gives consistent negative phd
        # while staying inside safe_delta. MAINT_BLEND is the hardest profile:
        # statistically identical to MAINT but process_health_delta trends negative.
        _attack_mode="coherent_drift"

    # ── ULTRA_SLOW — V10: redesigned dwell-only attacker (Failure 2) ─────
    else:  # ULTRA_SLOW
        # V10: ULTRA_SLOW is now a pure monitoring/dwell attacker.
        # write_ops=0 in 90% of rows. When writes occur, they are single isolated events.
        # All parameters match Normal_OPS — indistinguishable from a monitoring session.
        client=random.choice(KNOWN_CLIENT_NAMES+CONTRACTOR_CLIENT_NAMES); clsid=random.choice(KNOWN_CLSIDS)
        has_cert=random.random()<0.85
        auth,sec_mode,sec_pol,_=_security_posture(legacy_prob=0.10)
        # V10: service weights match Normal_OPS READ-heavy distribution
        service=random.choices(["Read","Subscribe","Publish","Browse","CreateMonitoredItems"],
                                weights=[40,30,15,10,5],k=1)[0]
        tag=random.choice(TAG_NAMES)
        # V10 Failure 2: 90% zero writes (was 70%)
        write_ops=0 if random.random()<0.90 else random.randint(1,2)
        # V10: rpm matches Normal_OPS exactly
        rpm=_lognormal_int(12,0.8,2,60)
        unique=random.randint(1,15); duration=_lognormal_int(5000,1.1,500,35000)
        payload=random.randint(64,1024); resp_ms=_lognormal_int(50,0.9,5,300)
        failed_auth=0; login_st="Success"; sess_res="Success"
        privilege=random.choice(["Operator","Engineer","ReadOnly"])
        # V10: active_sessions and seen_cnt match Normal_OPS
        active_sess=_lognormal_int(20,0.9,5,80)
        whitelist=1; is_new=0; seen_cnt=_lognormal_int(200,1.2,20,5000)  # exact OPS
        geo_mis=0; access_out=0
        if ctx.get("is_maintenance",False) and random.random()<0.50: access_out=1
        status=random.choice(OPC_STATUS_OK)
        username=random.choice([f"op_user_{random.randint(1,20)}",f"eng_user_{random.randint(1,8)}",
                                  f"scada_svc_{random.randint(1,3)}"])
        tag_q="Good"; _attack_mode="camouflage"

    cert_thumb = _rng_cert_thumb() if has_cert else ""
    dtype = random.choice(TAG_DATA_TYPES)

    # V11: All value computation goes through the unified semantic function.
    # drift_sign is passed so camouflage/coherent_drift encode directional process intent.
    bv, av, delta, pct, legality, phd = _rng_tag_value_semantic(
        tag, dtype, severity, _attack_mode, op_mode, drift_sign=drift_sign
    )

    # V11: Extract process consequence tracking from session arc state
    _cum_phd = session_state.pop("_cumulative_phd_so_far", 0.0)
    _n_w = session_state.pop("_n_writes_seen", 0)
    is_write_row = (session_state.get("session_write_ratio", 0.0) > 0.0)
    _new_n_w = _n_w + (1 if is_write_row else 0)
    _new_cum = _cum_phd + phd
    # session_process_convergence: mean phd across write events — attacks trend negative
    sess_proc_conv = round(_new_cum / max(_new_n_w + 1, 1), 4)
    # cumulative_process_deviation: running signed sum — attacks accumulate negative
    cum_dev = round(_new_cum, 4)

    load_score = _operational_load_score(ctx, "ATTACK")
    burst_score = _activity_burst_score(rpm, "ATTACK")
    inter_arr = _lognormal_int(600, 1.0, 40, 8000)

    # V10 Failure 6 (Sequence): Human inconsistency — service override (20% chance for stealth)
    if profile in ("STEALTHY","GRADUAL","CAMOUFLAGE","MAINT_BLEND","ULTRA_SLOW"):
        if random.random() < 0.20:
            # Inject a "human mistake" service — operator checks status, reads back, etc.
            service = random.choices(
                ["Read","Browse","Subscribe","Read","Read"],  # biased toward read (human verifying)
                weights=[35,20,15,20,10], k=1
            )[0]
            # If this is now a read-type row, zero out write_ops
            if service in ("Read","Browse","Subscribe"):
                write_ops = 0

    # V8: attack chain phase
    _chain_phases = ["recon","establish","persist","execute","execute","exfil","cleanup"]
    _phase_idx = min(int(severity * len(_chain_phases)), len(_chain_phases) - 1)
    attack_phase = _chain_phases[_phase_idx]

    r.update({
        "src_ip":_rng_ip(private=True),"dst_ip":_rng_ip(private=True),
        "src_port":_rng_port(high_range=True),"dst_port":4840,
        "connection_duration_ms":duration,"opc_client_name":client,"opc_client_clsid":clsid,
        "opc_server_endpoint_url":_endpoint(),"client_certificate_thumbprint":cert_thumb,
        "authentication_method":auth,"security_mode":sec_mode,"security_policy":sec_pol,
        "opc_service_type":service,"opc_status_code":status,"response_time_ms":resp_ms,
        "payload_size_bytes":payload,"tag_name":tag,"tag_data_type":dtype,
        "tag_value_before":bv,"tag_value_after":av,"tag_quality":tag_q,
        "tag_access_rights":"ReadWrite","value_change_delta":delta,"value_change_percent":pct,
        "username":username,"login_status":login_st,"failed_auth_count":failed_auth,
        "privilege_level":privilege,"session_activation_result":sess_res,
        "is_new_client":is_new,"client_first_seen_timestamp":ts,"client_seen_count":seen_cnt,
        "requests_per_minute":rpm,"unique_tags_accessed":unique,"write_ops_in_window":write_ops,
        "access_outside_business_hours":access_out,"geo_location_mismatch":geo_mis,
        "client_known_to_whitelist":whitelist,"hour_of_day":ctx["hour"],"shift_id":ctx["shift_id"],
        "business_hours":int(ctx["is_business_hours"]),"maintenance_window":int(ctx["is_maintenance"]),
        "is_weekend":int(ctx["is_weekend"]),"activity_burst_score":burst_score,
        "session_interarrival_ms":inter_arr,"operational_load_score":load_score,
        **session_state,"label":2,"label_str":"Tag Modification Detected",
        "behavioral_profile":f"TagModification_{profile}",
        "value_semantic_legality":legality,"attack_chain_phase":attack_phase,
        "process_health_delta":phd,
        "session_process_convergence":sess_proc_conv,
        "cumulative_process_deviation":cum_dev,
    })
    r=_inject_env_chaos(r,ctx,class_label=2); return r


def generate_tagmod_session() -> list:
    """
    V10: 7 profiles. Profile weights designed for realistic recall ~92–96%.
    MAINT_BLEND and CAMOUFLAGE are hardest (most confusion with Normal).
    ULTRA_SLOW redesigned as pure dwell-monitoring with rare isolated writes.

    V10 session_meta: carries drift_sign for coherent directional sabotage.
    """
    ctx = _temporal_context()

    profile = random.choices(
        ["OBVIOUS","MODERATE","STEALTHY","GRADUAL","ULTRA_SLOW","CAMOUFLAGE","MAINT_BLEND"],
        weights=[7, 28, 20, 12, 8, 11, 14], k=1
    )[0]

    # Temporal context selection per profile
    if profile in ("STEALTHY", "GRADUAL"):
        ctx = _stealth_temporal_context()
    elif profile == "ULTRA_SLOW" and random.random() < 0.60:
        ctx = _stealth_temporal_context()
    elif profile == "CAMOUFLAGE":
        ctx["is_maintenance"] = True; ctx["outside_hours"] = True
        ctx["hour"] = random.choice(list(range(1,6)) + [22,23])
        ctx["op_mode"] = "MAINTENANCE_MODE"
        if random.random() < 0.50: ctx["shift_id"]=2; ctx["reduced_staffing"]=True
    elif profile == "MAINT_BLEND":
        # Use exact same temporal context logic as Normal_MAINT
        if not ctx["is_maintenance"]:
            if random.random() < 0.70: ctx["is_maintenance"]=True; ctx["outside_hours"]=True
        if ctx["shift_id"] != 2 and random.random() < 0.40:
            ctx["shift_id"]=2; ctx["reduced_staffing"]=True
            ctx["hour"]=random.choice(list(range(0,6))+[22,23])
            ctx["is_maintenance"]=True; ctx["outside_hours"]=True
            ctx["op_mode"]="MAINTENANCE_MODE"

    # V10: session_meta carries drift_sign for coherent drift across rows
    session_meta = {"drift_sign": random.choice([-1, 1])}

    # Session lengths and arc types
    if profile == "OBVIOUS":
        n_rows=random.randint(2,10); session_type="attack_persist"; base_sev=random.uniform(0.70,1.0)
    elif profile == "MODERATE":
        n_rows=random.randint(3,18); session_type="attack_persist"; base_sev=random.uniform(0.30,0.75)
    elif profile == "STEALTHY":
        # V10: use attack_stealth_maint arc — identical phases to normal_maint
        n_rows=random.randint(5,22); session_type="attack_stealth_maint"; base_sev=random.uniform(0.03,0.25)
    elif profile == "GRADUAL":
        # V10: use attack_stealth_maint arc — identical phases to normal_maint
        n_rows=random.randint(6,30); session_type="attack_stealth_maint"; base_sev=random.uniform(0.003,0.08)
    elif profile == "CAMOUFLAGE":
        n_rows=random.randint(6,25); session_type="attack_camouflage"; base_sev=random.uniform(0.001,0.06)
    elif profile == "MAINT_BLEND":
        # V10: use normal_maint arc exactly — same phase sequence as legitimate maintenance
        n_rows=random.randint(4,20); session_type="normal_maint"; base_sev=random.uniform(0.001,0.05)
    else:  # ULTRA_SLOW
        # V10: use attack_ultra_slow or attack_phantom arc
        if random.random() < 0.35:
            session_type = "attack_phantom"   # zero writes — pure dwell
            base_sev = 0.0
        else:
            session_type = "attack_ultra_slow"  # very rare isolated writes
            base_sev = random.uniform(0.001, 0.03)
        n_rows = random.randint(10, 40)  # V10: much longer sessions

    arc = _make_session_arc(n_rows, session_type, ctx=ctx, session_meta=session_meta)

    rows = []
    escalation_rates = {
        "OBVIOUS":0.20, "MODERATE":0.15, "STEALTHY":0.04,
        "GRADUAL":0.02, "CAMOUFLAGE":0.01, "MAINT_BLEND":0.01, "ULTRA_SLOW":0.005,
    }
    esc = escalation_rates.get(profile, 0.05)
    for i in range(n_rows):
        sev = min(1.0, base_sev + (i / max(n_rows, 1)) * esc)
        rows.append(_build_tagmod_row(ctx, profile, arc[i], sev, session_meta))
    return rows


# ─────────────────────────────────────────────────────────────────────────────
#  NEW CLIENT  (unchanged from V9)
# ─────────────────────────────────────────────────────────────────────────────

def _build_newclient_row(ctx, profile, session_state: dict) -> dict:
    r=_base_row(); ts=_ts_from_context(ctx); r["timestamp"]=ts; severity=0.0
    if profile=="RECON":
        client=random.choice(UNKNOWN_CLIENT_NAMES); clsid=random.choice(UNKNOWN_CLSIDS)
        has_cert=random.random()<0.15; auth=random.choice(["Anonymous","Username"])
        sec_mode=random.choice(["None","Sign"]); sec_pol="None" if sec_mode=="None" else "Basic128Rsa15"
        service=random.choices(["Browse","Browse","Browse","Read","CreateSession","Subscribe"],weights=[45,20,10,10,10,5],k=1)[0]
        is_new=1; seen_cnt=random.randint(1,6); rpm=_lognormal_int(35,1.0,8,100); unique=random.randint(15,60)
        write_ops=random.randint(0,3); failed_auth=random.randint(0,6)
        login_st=random.choices(["Success","Success","Failure"],weights=[50,30,20])[0]
        sess_res="Success" if login_st=="Success" else random.choice(["Failed","Success"])
        whitelist=0; privilege=random.choice(["Guest","ReadOnly"]); geo_mis=int(random.random()<0.45)
        access_out=int(ctx["outside_hours"]) if random.random()<0.40 else 0
        duration=_lognormal_int(3000,1.1,500,20000); payload=random.randint(256,4096); resp_ms=_lognormal_int(150,1.0,30,800)
        status=random.choice(OPC_STATUS_OK+OPC_STATUS_BAD[:3])
        username=random.choice(["anonymous","guest",f"new_user_{random.randint(100,999)}"])
        tag_q=random.choices(["Good","Uncertain"],weights=[65,35])[0]; active_sess=_lognormal_int(5,0.8,1,20)
    elif profile=="PASSIVE":
        spoof=random.random()<0.15; known_client=random.random()<0.20
        client=random.choice(CONTRACTOR_CLIENT_NAMES if known_client else UNKNOWN_CLIENT_NAMES)
        clsid=random.choice(UNKNOWN_CLSIDS); has_cert=random.random()<0.30
        auth=random.choice(["Username","Anonymous"]); sec_mode=random.choice(["None","Sign"])
        sec_pol="None" if sec_mode=="None" else "Basic128Rsa15"
        service=random.choices(["Read","Subscribe","Browse","CreateMonitoredItems"],weights=[45,30,15,10],k=1)[0]
        is_new=0 if spoof else 1; seen_cnt=random.randint(20,200) if spoof else random.randint(1,8)
        rpm=_lognormal_int(12,0.9,2,38); unique=random.randint(8,25); write_ops=0
        failed_auth=random.randint(0,4); login_st=random.choices(["Success","Success","Failure"],weights=[60,25,15])[0]
        sess_res="Success" if login_st=="Success" else "Failed"
        whitelist=0; privilege=random.choice(["ReadOnly","Guest","Operator"]); geo_mis=int(random.random()<0.35)
        access_out=int(ctx["outside_hours"]) if random.random()<0.35 else 0
        duration=_lognormal_int(8000,1.2,1000,60000); payload=random.randint(256,2048); resp_ms=_lognormal_int(200,1.0,50,1000)
        status=random.choice(OPC_STATUS_OK+OPC_STATUS_UNCERTAIN)
        username=random.choice([f"new_user_{random.randint(100,999)}","discovery_svc","anonymous",f"vendor_{random.randint(1,5)}"])
        tag_q=random.choices(["Good","Uncertain"],weights=[75,25])[0]; active_sess=_lognormal_int(5,0.8,1,22)
    elif profile=="ONBOARD":
        client=random.choice(CONTRACTOR_CLIENT_NAMES+KNOWN_CLIENT_NAMES[-3:])
        clsid=random.choice(KNOWN_CLSIDS+UNKNOWN_CLSIDS[:2]); has_cert=random.random()<0.62
        auth,sec_mode,sec_pol,_=_security_posture(legacy_prob=0.20)
        service=random.choices(["Browse","Read","CreateSession","Subscribe","CloseSession"],weights=[30,30,20,15,5],k=1)[0]
        is_new=1; seen_cnt=random.randint(1,5); rpm=_lognormal_int(15,0.9,3,50); unique=random.randint(10,40)
        write_ops=random.randint(0,5); failed_auth=random.randint(0,5)
        login_st=random.choices(["Success","Failure","Success"],weights=[55,25,20])[0]
        sess_res="Success" if login_st=="Success" else random.choice(["Failed","Success"])
        whitelist=0; privilege=random.choice(["ReadOnly","Operator","Guest"]); geo_mis=int(random.random()<0.30)
        access_out=int(ctx["outside_hours"]) if random.random()<0.25 else 0
        duration=_lognormal_int(4000,1.1,300,25000); payload=random.randint(128,2048); resp_ms=_lognormal_int(120,1.0,20,600)
        status=random.choice(OPC_STATUS_OK+OPC_STATUS_BAD[:2]+OPC_STATUS_UNCERTAIN)
        username=random.choice([f"vendor_{random.randint(1,5)}",f"contractor_{random.randint(1,10)}",f"new_eng_{random.randint(1,5)}"])
        tag_q=random.choices(["Good","Uncertain"],weights=[80,20])[0]; active_sess=_lognormal_int(8,0.8,2,30)
    else:  # INFILTRAT
        known_client=random.random()<0.65; op=_pick_remote_operator() if random.random()<0.40 else None
        client=random.choice(KNOWN_CLIENT_NAMES if known_client else UNKNOWN_CLIENT_NAMES)
        clsid=random.choice(KNOWN_CLSIDS if known_client else UNKNOWN_CLSIDS)
        has_cert=known_client and random.random()<0.72
        auth="Username" if known_client else random.choice(["Username","Anonymous"])
        sec_mode=random.choice(["Sign","SignAndEncrypt"]) if known_client else "Sign"
        sec_pol="Basic256Sha256" if sec_mode!="None" else "None"
        service=random.choices(["Read","Browse","Subscribe","Write","CloseSession"],weights=[30,30,20,15,5],k=1)[0]
        is_new=1; seen_cnt=random.randint(3,25); rpm=_lognormal_int(20,0.9,5,60); unique=random.randint(12,35)
        write_ops=random.randint(1,10); failed_auth=random.randint(0,3); login_st="Success"; sess_res="Success"
        whitelist=int(known_client); privilege=random.choice(["ReadOnly","Operator","Engineer"])
        geo_mis=int(random.random()<0.20); access_out=int(ctx["is_maintenance"]) if random.random()<0.40 else 0
        duration=_lognormal_int(10000,1.0,2000,60000); payload=random.randint(256,2048); resp_ms=_lognormal_int(80,0.9,15,500)
        status=random.choice(OPC_STATUS_OK+OPC_STATUS_UNCERTAIN)
        username=op["username"] if op else random.choice([f"op_user_{random.randint(1,20)}",f"vendor_{random.randint(1,5)}",f"eng_user_{random.randint(1,5)}"])
        tag_q="Good"; severity=0.1; active_sess=_lognormal_int(14,0.9,4,50)

    cert_thumb=_rng_cert_thumb() if has_cert else ""; dtype=random.choice(TAG_DATA_TYPES); tag=random.choice(TAG_NAMES)
    bv,av,delta,pct=_rng_tag_value(dtype,severity=severity)
    load_score=_operational_load_score(ctx,"ATTACK"); burst_score=_activity_burst_score(rpm,"ATTACK")
    inter_arr=_lognormal_int(700,1.0,50,9000); legality=round(random.gauss(0.75,0.18),4)
    r.update({
        "src_ip":_rng_ip(private=(random.random()<0.55)),"dst_ip":_rng_ip(private=True),
        "src_port":_rng_port(high_range=True),"dst_port":random.choice([4840,4843]),
        "connection_duration_ms":duration,"opc_client_name":client,"opc_client_clsid":clsid,
        "opc_server_endpoint_url":_endpoint(),"client_certificate_thumbprint":cert_thumb,
        "authentication_method":auth,"security_mode":sec_mode,"security_policy":sec_pol,
        "opc_service_type":service,"opc_status_code":status,"response_time_ms":resp_ms,
        "payload_size_bytes":payload,"tag_name":tag,"tag_data_type":dtype,"tag_value_before":bv,
        "tag_value_after":av,"tag_quality":tag_q,"tag_access_rights":random.choice(["Read","ReadWrite"]),
        "value_change_delta":delta,"value_change_percent":pct,"username":username,
        "login_status":login_st,"failed_auth_count":failed_auth,"privilege_level":privilege,
        "session_activation_result":sess_res,"is_new_client":is_new,"client_first_seen_timestamp":ts,
        "client_seen_count":seen_cnt,"requests_per_minute":rpm,"unique_tags_accessed":unique,
        "write_ops_in_window":write_ops,"access_outside_business_hours":access_out,
        "geo_location_mismatch":geo_mis,"client_known_to_whitelist":whitelist,
        "hour_of_day":ctx["hour"],"shift_id":ctx["shift_id"],"business_hours":int(ctx["is_business_hours"]),
        "maintenance_window":int(ctx["is_maintenance"]),"is_weekend":int(ctx["is_weekend"]),
        "activity_burst_score":burst_score,"session_interarrival_ms":inter_arr,
        "operational_load_score":load_score,**session_state,
        "value_semantic_legality":max(0.0,min(1.0,legality)),
        "process_health_delta":0.0,"session_process_convergence":0.0,
        "cumulative_process_deviation":0.0,
        "label":3,"label_str":"New Client Detected Alert","behavioral_profile":f"NewClient_{profile}",
    })
    r=_inject_env_chaos(r,ctx,class_label=3); return r

def generate_newclient_session() -> list:
    ctx=_temporal_context()
    profile=random.choices(["RECON","PASSIVE","ONBOARD","INFILTRAT"],weights=[33,30,25,12],k=1)[0]
    if profile=="RECON": n_rows=random.randint(3,15); session_type="attack_recon"
    elif profile=="PASSIVE": n_rows=random.randint(4,20); session_type="attack_recon"
    elif profile=="ONBOARD": n_rows=random.randint(2,10); session_type="normal_ops"
    else: n_rows=random.randint(5,25); session_type="attack_persist"
    arc=_make_session_arc(n_rows,session_type,ctx=ctx)
    return [_build_newclient_row(ctx,profile,arc[i]) for i in range(n_rows)]


# ─────────────────────────────────────────────────────────────────────────────
#  LABEL NOISE
# ─────────────────────────────────────────────────────────────────────────────

_NOISE_MAP = {0:[1,3], 1:[0,3], 2:[0], 3:[0,1]}
_LABEL_STR = {0:"Normal",1:"Unauthorized Access",2:"Tag Modification Detected",3:"New Client Detected Alert"}

def _apply_label_noise(row: dict) -> dict:
    if random.random() < LABEL_NOISE_PROB:
        orig=row["label"]; noisy=random.choice(_NOISE_MAP[orig])
        row["label"]=noisy; row["label_str"]=_LABEL_STR[noisy]
    return row


# ─────────────────────────────────────────────────────────────────────────────
#  SESSION-BASED DISPATCH
# ─────────────────────────────────────────────────────────────────────────────

def _session_stream(total_rows: int, distribution: dict):
    session_generators = {
        0: generate_normal_session, 1: generate_unauthorized_session,
        2: generate_tagmod_session, 3: generate_newclient_session,
    }
    counts = {}; allocated = 0; labels = list(distribution.keys())
    for lbl in labels[:-1]:
        n=round(total_rows*distribution[lbl]); counts[lbl]=n; allocated+=n
    counts[labels[-1]]=total_rows-allocated
    remaining=dict(counts); total_emitted=0; class_list=list(distribution.keys())
    while total_emitted < total_rows:
        avail=[c for c in class_list if remaining.get(c,0)>0]
        if not avail: break
        total_w=sum(distribution[c] for c in avail)
        norm_w=[distribution[c]/total_w for c in avail]
        chosen=random.choices(avail,weights=norm_w,k=1)[0]
        try: session_rows=session_generators[chosen]()
        except Exception: session_rows=[]
        for row in session_rows:
            if remaining.get(chosen,0)<=0: break
            row=_apply_label_noise(row); yield row
            remaining[chosen]-=1; total_emitted+=1
            if total_emitted>=total_rows: return


# ─────────────────────────────────────────────────────────────────────────────
#  COLUMNS
# ─────────────────────────────────────────────────────────────────────────────

COLUMNS = [
    "timestamp","src_ip","dst_ip","src_port","dst_port","protocol",
    "session_id","connection_duration_ms","opc_client_name",
    "opc_client_clsid","opc_server_name","opc_server_endpoint_url",
    "opc_server_node_id","client_certificate_thumbprint",
    "authentication_method","security_mode","security_policy",
    "opc_service_type","opc_request_id","opc_status_code",
    "response_time_ms","payload_size_bytes","tag_name","tag_node_id",
    "tag_data_type","tag_value_before","tag_value_after","tag_quality",
    "tag_access_rights","value_change_delta","value_change_percent",
    "username","user_domain","login_status","failed_auth_count",
    "privilege_level","session_activation_result","is_new_client",
    "client_first_seen_timestamp","client_seen_count","requests_per_minute",
    "unique_tags_accessed","write_ops_in_window",
    "access_outside_business_hours","geo_location_mismatch",
    "client_known_to_whitelist","hour_of_day","shift_id","business_hours",
    "maintenance_window","is_weekend","activity_burst_score",
    "session_interarrival_ms","operational_load_score",
    "session_duration_total","session_request_variance","session_write_ratio",
    "session_unique_tags","session_behavior_entropy","session_event_index",
    "session_state_transition_count","session_idle_gap_ms","session_temporal_drift",
    "action_transition_rarity","value_semantic_legality","attack_chain_phase",
    "process_health_delta","session_process_convergence","cumulative_process_deviation",
    "label","label_str","behavioral_profile",
]


# ─────────────────────────────────────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────────────────────────────────────

def main():
    print("=" * 70)
    print("  OT/ICS SYNTHETIC DATASET GENERATOR — Behavioral Realism v11.0")
    print("  (Tag_Modification Long-Horizon Semantic Consequence — Surgical Build)")
    print("=" * 70)
    print(f"  Total rows  : {TOTAL_ROWS:,}")
    print(f"  Output file : {OUTPUT_FILE}")
    print(f"  Label noise : {LABEL_NOISE_PROB*100:.1f}%")
    print()
    print("  V11 TAG_MOD SEMANTIC CONSEQUENCE OVERHAUL (9 realism fixes):")
    print("    F1 ✓  NEW: process_health_delta — per-write convergence/divergence signal")
    print("           Maintenance: phd > 0 (corrective). Attacks: phd < 0 (divergent).")
    print("           Even CAMOUFLAGE/MAINT_BLEND carry small but consistent negative phd.")
    print("    F2 ✓  NEW: session_process_convergence — rolling mean phd within session")
    print("           Maintenance sessions trend positive. Attack sessions trend negative.")
    print("    F3 ✓  NEW: cumulative_process_deviation — signed session sum of phd")
    print("           Long-horizon signal: maintenance sessions sum to +N, attacks to -N.")
    print("    F4 ✓  Maintenance writes now CORRECTIVE — after-value moves TOWARD setpoint")
    print("           (70% corrective, 30% neutral). phd explicitly positive for MAINT/CALIB.")
    print("    F5 ✓  CAMOUFLAGE: 55% deceptive stabilization + hidden counter-nudge")
    print("           Locally appears corrective. Globally phd accumulates negative.")
    print("    F6 ✓  COHERENT_DRIFT: drift_sign now passed into semantic function")
    print("           phd explicitly biased negative: attacks diverge from setpoint.")
    print("    F7 ✓  All stealth profiles: phd biased -0.02 to -0.25 per write row")
    print("           Maintenance profiles: phd biased +0.08 to +0.20 per write row.")
    print("    F8 ✓  MAINT_BLEND: uses coherent_drift attack_mode (not camouflage)")
    print("           Gives it a consistent small-negative phd while matching MAINT stats.")
    print("    F9 ✓  All other V10 fixes preserved: statistical overlap, arc realism,")
    print("           write separation, human inconsistency, ultra_slow dwell design.")
    print()
    print("  V11 CORE SEMANTIC DISTINCTION:")
    print("    Maintenance: local noise + global convergence (phd > 0, session sum > 0)")
    print("    Attacks:     local legitimacy + global divergence (phd < 0, session sum < 0)")
    print("    The IDS must learn: WHO BENEFITS FROM THE WRITE, not HOW IT LOOKS.")
    print()
    print("  V11 PROFILE WEIGHTS (unchanged from V10):")
    profile_info = [
        ("OBVIOUS",    7,  "clearly detectable"),
        ("MODERATE",  28,  "moderately detectable"),
        ("STEALTHY",  20,  "hard — operator mimicry + maintenance arc"),
        ("GRADUAL",   12,  "very hard — calibration-scale drift"),
        ("ULTRA_SLOW", 8,  "extremely hard — dwell-only, rare writes"),
        ("CAMOUFLAGE",11,  "hardest — indistinguishable from CALIBRATION"),
        ("MAINT_BLEND",14, "hardest — indistinguishable from MAINT"),
    ]
    for name, w, desc in profile_info:
        print(f"    {name:12s}: {w:2d}%  ({desc})")
    print()
    print("  EXPECTED REALISTIC IDS BEHAVIOR (V11 target):")
    print("    Tag_Modification Precision: 92–95%  (precision restored via phd signal)")
    print("    Tag_Modification Recall:    93–96%  (preserved — stealth overlap unchanged)")
    print("    Tag_Modification F1:        92–95%  (healthy balance restored)")
    print("    Tag_Modification ROC-AUC:   0.94–0.97  (realistic — not near-perfect)")
    print("    Key confusion: TagMod↔Normal_MAINT on MAINT_BLEND (intended)")
    print("    Key learnable signal: process_health_delta + session_process_convergence")
    print()
    for lbl, frac in CLASS_DISTRIBUTION.items():
        n=round(TOTAL_ROWS*frac)
        print(f"  [{lbl}] {ATTACK_CONFIG[lbl]['label_str']:38s}  {frac*100:.2f}%  → ~{n:,} rows")
    print("=" * 70)

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    rows_written = 0
    stream = _session_stream(TOTAL_ROWS, CLASS_DISTRIBUTION)

    with open(OUTPUT_FILE, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=COLUMNS, extrasaction="ignore")
        writer.writeheader()
        while rows_written < TOTAL_ROWS:
            batch_size = min(CHUNK_SIZE, TOTAL_ROWS - rows_written)
            batch = list(islice(stream, batch_size))
            if not batch: break
            writer.writerows(batch)
            rows_written += len(batch)
            pct = rows_written / TOTAL_ROWS * 100
            bar = "█" * int(pct // 2) + "░" * (50 - int(pct // 2))
            print(f"\r  [{bar}] {pct:6.2f}%  {rows_written:,}/{TOTAL_ROWS:,}", end="", flush=True)

    print(f"\n\n  ✓ Done!  {rows_written:,} rows written to: {OUTPUT_FILE}")
    size_mb = os.path.getsize(OUTPUT_FILE) / (1024 ** 2)
    print(f"  File size : {size_mb:,.1f} MB  ({size_mb/1024:.2f} GB)")
    print("=" * 70)


if __name__ == "__main__":
    main()
