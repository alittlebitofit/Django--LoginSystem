import hashlib
import hmac
import math
import time

import base64
import qrcode

import random
import os

import shutil

import uuid


class Token:

	# Helper function - generates a 32-character 2FA token.
	def gen_token(self, user_username):
		'''Step 1: Generating a base32-encoded token'''

		random_number = random.randint(1000000000, 9999999999)
		current_time = int(time.time())

		string = user_username + str(random_number) + str(current_time)

		l = list(string)

		k = ''

		for i in range(20):
			k += str(l.pop(random.randrange(len(l))))

		key = bytes(k, 'utf-8')

		return key




	# Helper function - generates a QR code.
	def gen_qrcode(self, user_username, user_email, key):
		'''Step 2: Generating QR Code'''

		# Create a temporary directory to store qrcode if it doesn't already exist.
		path_to_img = 'signins/static/signins/tmp/'+user_username
		if not os.path.exists(path_to_img):
			os.makedirs(path_to_img)

		# Location to store QR code temporarily.
		image_path = path_to_img+'/token_qr.png'

		# Token.
		token = base64.b32encode(key)

		qr_string = 'otpauth://totp/Login-System:' + user_email + '?secret=' + token.decode('utf-8') + '&issuer=Login-System&algorithm=SHA1&digits=6&period=30'

		# This statement generates QR code.
		img = qrcode.make(qr_string)

		# This statement saves the QR code in a temporary location.
		img.save(image_path)





	# Helper function - generates TOTP
	def gen_totp(self, key):
		'''Step 3: Generating hmac hexdigest and TOTP'''

		# length of OTP in digits
		length = 6

		# timestamp or time-window for which the token is valid
		step_in_seconds = 30


		t = math.floor(time.time() // step_in_seconds)

		hmac_object = hmac.new(key, t.to_bytes(length=8, byteorder='big'), hashlib.sha1)
		hmac_sha1 = hmac_object.hexdigest()

		# truncate to 6 digits
		offset = int(hmac_sha1[-1], 16)
		binary = int(hmac_sha1[(offset * 2):((offset * 2) + 8)], 16) & 0x7fffffff
		totp = str(binary)[-length:]

		print(totp)
		return totp





	# Helper function - generates backup codes.
	def gen_backup_codes(self):
		backup_codes_list = []

		for i in range(10):
			backup_codes_list.append(uuid.uuid4().hex[:10].upper())

		return backup_codes_list



tokenRelated = Token()
