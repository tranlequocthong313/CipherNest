from enum import Enum


class Code(Enum):
    SUCCESS = "00"
    RUN_OUT_OF_FREE_SPACE = "01"
    NOT_EMBEDDED_BY_SYSTEM = "02"
    IS_EMBEDDED_BY_SYSTEM = "03"
    INTERNAL_SERVER_ERROR = "04"
    INVALID_REQUEST_DATA = "05"
    REQUIRE_PASSWORD = "05"
    WRONG_PASSWORD = "06"
    DATA_CORRUPTED = "07"


class Algorithm(Enum):
    LSB = "lsb"
    ECHO_HIDING = "echo_hiding"
    AMPLITUDE_ENCODING = "echo_hiding"
    SPREAD_SPECTRUM = "spread_spectrum"

OUTPUT_QUALITY=[
    ("very_low", "VERY_LOW"),
    ("low", "LOW"),
    ("medium", "MEDIUM"),
    ("high", "HIGH"),
]
