import logging
import settings
import pytz
from datetime import datetime

def log_writer(message):
    # Get current time in IST
    ist = pytz.timezone('Asia/Kolkata')
    current_time = datetime.now(ist)
    
    logging.basicConfig(
        filename=settings.log_file_path,
        encoding='utf-8',
        level=logging.INFO,
        format='[%(asctime)s] : %(message)s',
        datefmt='%d-%m-%Y %H:%M:%S IST'
    )
    logging.info(message)