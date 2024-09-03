from enum import Enum


class Code(Enum):
    SUCCESS = "00"
    RUN_OUT_OF_FREE_SPACE = "01"
    NOT_EMBEDDED_BY_SYSTEM = "02"
    IS_EMBEDDED_BY_SYSTEM = "03"
