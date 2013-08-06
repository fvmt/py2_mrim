import logging

def mrim_logger():
    logger = logging.getLogger('mrim')
    logger.setLevel(logging.DEBUG)
    # create file handler which logs even debug messages
    #fh = logging.FileHandler('spam.log')
    #fh.setLevel(logging.DEBUG)
    # create console handler
    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)
    # create formatter and add it to the handlers
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    #fh.setFormatter(formatter)
    ch.setFormatter(formatter)
    # add the handlers to the logger
    #logger.addHandler(fh)
    logger.addHandler(ch)
    return logger