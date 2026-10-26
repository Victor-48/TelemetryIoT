import random
from typing import Any, Dict, Optional


class ModbusPLCModel:
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.register_40001 = config.get("nominal", {}).get("register_40001", 140)
        self.register_40002 = config.get("nominal", {}).get("register_40002", 55)
        self.coil_1 = config.get("nominal", {}).get("coil_1", 1)
        self.coil_2 = 0
        self.injection_flag = 0

    def step(self, elapsed: float, override: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        if override:
            self.register_40001 = override.get("register_40001", self.register_40001)
            self.coil_1 = override.get("coil_1", self.coil_1)
            self.coil_2 = override.get("coil_2", self.coil_2)
            self.injection_flag = override.get("injection_flag", 1)
        else:
            # Baseline normal fluctuation
            self.register_40001 = int(140 + random.randint(-3, 3))
            self.register_40002 = int(55 + random.randint(-1, 1))

        return {
            "holding_register_40001": self.register_40001,
            "holding_register_40002": self.register_40002,
            "discrete_coil_01": self.coil_1,
            "discrete_coil_02": self.coil_2,
            "injection_flag": self.injection_flag
        }


class IndustrialFridgeModel:
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.temperature = -20.0
        self.compressor_state = 1
        self.drift_rate = 0.0

    def step(self, elapsed: float, override: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        if override:
            if "compressor_state" in override:
                self.compressor_state = override["compressor_state"]
            if "temperature_drift_rate" in override:
                self.drift_rate = override["temperature_drift_rate"]

        if self.compressor_state == 0:
            # Compressor disabled by attack: temperature rises rapidly
            self.temperature += self.drift_rate * 0.5 + random.uniform(0.1, 0.3)
        else:
            # Compressor active: maintain -22 to -18 with slight oscillation
            self.temperature = -20.0 + random.uniform(-1.0, 1.0)

        return {
            "temperature_celsius": round(self.temperature, 2),
            "compressor_relay": self.compressor_state,
            "door_seal_intact": 1
        }


class ThermostatModel:
    def __init__(self, config: Dict[str, Any]):
        self.target = config.get("nominal", {}).get("temperature_target", 22.0)
        self.current_temp = 22.0

    def step(self, elapsed: float, override: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        if override:
            self.current_temp = override.get("temperature", self.current_temp)
        else:
            self.current_temp = self.target + random.uniform(-0.6, 0.6)
        return {
            "ambient_temp_celsius": round(self.current_temp, 2),
            "target_setpoint": self.target,
            "heating_relay": 1 if self.current_temp < self.target else 0
        }


class GarageDoorModel:
    def __init__(self, config: Dict[str, Any]):
        self.state = "closed"
        self.unauthorized = 0

    def step(self, elapsed: float, override: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        if override:
            self.state = override.get("door_state", self.state)
            self.unauthorized = override.get("unauthorized", self.unauthorized)
        return {
            "door_position": self.state,
            "security_latch_engaged": 1 if self.state == "closed" else 0,
            "unauthorized_access_alert": self.unauthorized
        }


class MotionLightModel:
    def __init__(self, config: Dict[str, Any]):
        self.lux = 380

    def step(self, elapsed: float, override: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        motion = "active" if random.random() < 0.25 else "idle"
        lux = self.lux + random.randint(-15, 15)
        return {
            "ambient_lux": lux,
            "pir_motion_sensor": motion
        }


class WeatherStationModel:
    def __init__(self, config: Dict[str, Any]):
        self.humidity = 52.0
        self.pressure = 1015.0

    def step(self, elapsed: float, override: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        return {
            "humidity_percent": round(self.humidity + random.uniform(-1.0, 1.0), 1),
            "atmospheric_pressure_hpa": round(self.pressure + random.uniform(-0.5, 0.5), 1),
            "wind_speed_mps": round(max(0.0, 3.2 + random.uniform(-1.2, 1.2)), 2)
        }


class GPSTrackerModel:
    def __init__(self, config: Dict[str, Any]):
        self.lat = config.get("nominal", {}).get("latitude", 44.4268)
        self.lon = config.get("nominal", {}).get("longitude", 26.1025)

    def step(self, elapsed: float, override: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        jitter_lat = random.uniform(-0.00005, 0.00005)
        jitter_lon = random.uniform(-0.00005, 0.00005)
        return {
            "latitude": round(self.lat + jitter_lat, 6),
            "longitude": round(self.lon + jitter_lon, 6),
            "speed_kmh": round(random.uniform(0.1, 1.2), 2),
            "fix_quality": "3D_FIX"
        }


def get_device_model(device_key: str, config: Dict[str, Any]):
    models = {
        "modbus": ModbusPLCModel,
        "frigider": IndustrialFridgeModel,
        "termostat": ThermostatModel,
        "garaj": GarageDoorModel,
        "lumina": MotionLightModel,
        "meteo": WeatherStationModel,
        "gps": GPSTrackerModel,
    }
    model_class = models.get(device_key)
    if not model_class:
        raise ValueError(f"Unknown device key: {device_key}")
    return model_class(config)
