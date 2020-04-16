#!/usr/bin/env python3
__copyright__ = """
	Copyright 2020 EPFL

	Licensed under the Apache License, Version 2.0 (the "License");
	you may not use this file except in compliance with the License.
	You may obtain a copy of the License at

		http://www.apache.org/licenses/LICENSE-2.0

	Unless required by applicable law or agreed to in writing, software
	distributed under the License is distributed on an "AS IS" BASIS,
	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
	See the License for the specific language governing permissions and
	limitations under the License.

"""
__license__ = "Apache 2.0"

import time
from datetime import datetime, timedelta

from LowCostDP3T import KeyStore, BROADCAST_KEY
import secrets
import hashlib
import hmac
 
null_secret = b"\0" * 16

print("Secret: {}".format(null_secret.hex()))

print("Broadcast-key: {}".format(BROADCAST_KEY.encode().hex()))

prf = hmac.new(null_secret, BROADCAST_KEY.encode(), hashlib.sha256).digest()
print("PRF:    {}".format(prf.hex()))

ks = KeyStore()
ks.SKt = []
ks.SKt.insert(0, null_secret)

ephIDs = ks.create_ephIDs(ks.SKt[0])

for i,e in enumerate(ephIDs[0:9]):
  print("{}\t{}".format(i,e.hex()))


