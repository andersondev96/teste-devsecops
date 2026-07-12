import os

SECRET_KEY = os.getenv("SECRET_KEY", "b3_ch4r_r4nd0m_s7r1ng_s4f3_f0r_7cc")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30