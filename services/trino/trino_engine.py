from sqlalchemy import create_engine , text
import os
import traceback
from util.logger_util import logger

def get_connection():

    TRINO_HOST  = os.getenv("TRINO_HOST", "localhost")
    TRINO_PORT  = os.getenv("TRINO_PORT", "8080")
    TRINO_USER_ID  = os.getenv("TRINO_USER_ID", "admin")
    # TRINO_CATALOG  = os.getenv("TRINO_CATALOG", "iceberg")
    
    try:
        connect_str = f"trino://{TRINO_USER_ID}@{TRINO_HOST}:{TRINO_PORT}"

        logger().info(connect_str)

        engine = create_engine(connect_str)

        return engine.connect()
    except Exception as e:
        # traceback.print_exception(e)
        tb = traceback.TracebackException.from_exception(e)
        print('Handled at stack lvl 0')
        print(''.join(tb.stack.format()))

        # logger().info(desired_trace)
        return logger().info(e)