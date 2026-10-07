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


import threading, logging

class Notification():
    def __init__(self, key, msg = None):
        if type(key) is not str:
            raise TypeError("Invalid notification key: "+str(key))
        self.key = key
        self.msg = msg

    def __repr__(self):
        return "Notification (key: %s, msg: %s)" % (str(self.key), str(self.msg))

class Notifier():
    def __init__(self, callbacks = [], **kwargs):
        self.callbacks = {}
        self.callbackLock = threading.RLock()

        for callback in callbacks:
            self.subscribe(*callback)

    def clearCallbacks(self):
        with self.callbackLock:
            self.callbacks.clear()

    def subscribe(self, key, callback):
        with self.callbackLock:
            if callback not in self.getCallbacks(key):
                self.getCallbacks(key).append(callback)

    def unSubscribe(self, key, callback):
        with self.callbackLock:
            if callback in self.getCallbacks(key):
                self.getCallbacks(key).remove(callback)

    def getCallbacks(self, key):
        with self.callbackLock:
            if key not in self.callbacks:
                self.callbacks[key] = []
            return self.callbacks[key]

    def notify(self, key = None, msg = None, notification = None):
        with self.callbackLock:
            if notification == None:
                notification = Notification(key,msg)

            for callback in self.getCallbacks(notification.key):
                callback(notification)

            for callback in self.getCallbacks("*"):
                callback(notification)

    def passOnNotification(self, notification):
        self.notify(notification = notification)
