# import os
# print(__file__)
# print(os.path.abspath(__file__))
# print(os.path.dirname(os.path.abspath(__file__)))
# print(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"))

import os
from dotenv import load_dotenv

load_dotenv()
print((os.getenv("DB_PASSWORD")))