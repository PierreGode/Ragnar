# Copyright (c) Nordic Semiconductor ASA
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without modification,
# are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this
#    list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form, except as embedded into a Nordic
#    Semiconductor ASA integrated circuit in a product or a software update for
#    such product, must reproduce the above copyright notice, this list of
#    conditions and the following disclaimer in the documentation and/or other
#    materials provided with the distribution.
#
# 3. Neither the name of Nordic Semiconductor ASA nor the names of its
#    contributors may be used to endorse or promote products derived from this
#    software without specific prior written permission.
#
# 4. This software, with or without modification, must only be used with a
#    Nordic Semiconductor ASA integrated circuit.
#
# 5. Any software provided in binary form under this license must not be reverse
#    engineered, decompiled, modified and/or disassembled.
#
# THIS SOFTWARE IS PROVIDED BY NORDIC SEMICONDUCTOR ASA "AS IS" AND ANY EXPRESS
# OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
# OF MERCHANTABILITY, NONINFRINGEMENT, AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL NORDIC SEMICONDUCTOR ASA OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
# GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
# OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


import time, os, logging, traceback, threading
import logging.handlers as logHandlers

#################################################################
# This file contains the logger. To log a line, simply write    #
# 'logging.[level]("whatever you want to log")'                 #
# [level] is one of {info, debug, warning, error, critical,     #
#     exception}                                                #
# See python logging documentation                              #
# As long as Logger.initLogger has been called beforehand, this #
# will result in the line being appended to the log file        #
#################################################################

appdata = os.getenv('appdata')
if appdata:
    DEFAULT_LOG_FILE_DIR = os.path.join(appdata, 'Nordic Semiconductor', 'Sniffer', 'logs')
else:
    DEFAULT_LOG_FILE_DIR = "/tmp/logs"

DEFAULT_LOG_FILE_NAME = "log.txt"

logFileName = None
logHandler = None
logHandlerArray = []
logFlusher = None

myMaxBytes = 1000000


def setLogFileName(log_file_path):
    global logFileName
    logFileName = os.path.abspath(log_file_path)


# Ensure that the directory we are writing the log file to exists.
# Create our logfile, and write the timestamp in the first line.
def initLogger():
    try:
        global logFileName
        if logFileName is None:
            logFileName = os.path.join(DEFAULT_LOG_FILE_DIR, DEFAULT_LOG_FILE_NAME)

        # First, make sure that the directory exists
        if not os.path.isdir(os.path.dirname(logFileName)):
            os.makedirs(os.path.dirname(logFileName))

        # If the file does not exist, create it, and save the timestamp
        if not os.path.isfile(logFileName):
            with open(logFileName, "w") as f:
                f.write(str(time.time()) + str(os.linesep))

        global logFlusher
        global logHandlerArray

        logHandler = MyRotatingFileHandler(logFileName, mode='a', maxBytes=myMaxBytes, backupCount=3)
        logFormatter = logging.Formatter('%(asctime)s %(levelname)s: %(message)s', datefmt='%d-%b-%Y %H:%M:%S (%z)')
        logHandler.setFormatter(logFormatter)
        logger = logging.getLogger()
        logger.addHandler(logHandler)
        logger.setLevel(logging.INFO)
        logFlusher = LogFlusher(logHandler)
        logHandlerArray.append(logHandler)
    except:
        print("LOGGING FAILED")
        print(traceback.format_exc())
        raise


def shutdownLogger():
    if logFlusher is not None:
        logFlusher.stop()
    logging.shutdown()


# Clear the log (typically after it has been sent on email)
def clearLog():
    try:
        logHandler.doRollover()
    except:
        print("LOGGING FAILED")
        raise


# Returns the timestamp residing on the first line of the logfile. Used for checking the time of creation
def getTimestamp():
    try:
        with open(logFileName, "r") as f:
            f.seek(0)
            return f.readline()
    except:
        print("LOGGING FAILED")


def addTimestamp():
    try:
        with open(logFileName, "a") as f:
            f.write(str(time.time()) + os.linesep)
    except:
        print("LOGGING FAILED")


# Returns the entire content of the logfile. Used when sending emails
def readAll():
    try:
        text = ""
        with open(logFileName, "r") as f:
            text = f.read()
        return text
    except:
        print("LOGGING FAILED")


def addLogHandler(logHandler):
    global logHandlerArray
    logger = logging.getLogger()
    logger.addHandler(logHandler)
    logger.setLevel(logging.INFO)
    logHandlerArray.append(logHandler)

def removeLogHandler(logHandler):
    global logHandlerArray
    logger = logging.getLogger()
    logger.removeHandler(logHandler)
    logHandlerArray.remove(logHandler)


class MyRotatingFileHandler(logHandlers.RotatingFileHandler):
    def doRollover(self):
        try:
            logHandlers.RotatingFileHandler.doRollover(self)
            addTimestamp()
            self.maxBytes = myMaxBytes
        except:
            # There have been permissions issues with the log files.
            self.maxBytes += int(myMaxBytes / 2)


class LogFlusher(threading.Thread):
    def __init__(self, logHandler):
        threading.Thread.__init__(self)

        self.daemon = True
        self.handler = logHandler
        self.exit = threading.Event()

        self.start()

    def run(self):
        while True:
            if self.exit.wait(10):
                try:
                    self.doFlush()
                except AttributeError as e:
                    print(e)
                break
            self.doFlush()

    def doFlush(self):
        self.handler.flush()
        os.fsync(self.handler.stream.fileno())

    def stop(self):
        self.exit.set()


if __name__ == '__main__':
    initLogger()
    for i in range(50):
        logging.info("test log no. " + str(i))
        print("test log no. ", i)
