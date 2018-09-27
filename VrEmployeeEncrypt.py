import base64
import hashlib
from Crypto import Random
from Crypto.Cipher import AES

from odoo import models, fields, api
from odoo.tools import ormcache
from odoo.models import BaseModel


class VrEmployeeEncrypt(models.Model):
    _inherit = 'vr.employee'

    bs = 32
    secret_key = 'jamesforlifesog'
    key = hashlib.sha512(secret_key.encode()).digest()[:16]
    def encrypt(self, raw):
        raw = self._pad(raw)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(raw))

    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        iv = enc[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return self._unpad(cipher.decrypt(enc[AES.block_size:])).decode('utf-8')

    def _pad(self, s):
        return s + (self.bs - len(s) % self.bs) * chr(self.bs - len(s) % self.bs)

    @staticmethod
    def _unpad(s):
        return s[:-ord(s[len(s)-1:])]

    @api.model
    def create(self, vals):
        if 'ssn' in vals.keys():
            if vals['ssn'] is not False:
                vals.update({'ssn': self.encrypt(vals['ssn'])})
        return super(VrEmployeeEncrypt, self).create(vals)

    @api.multi
    def write(self, vals):
        if 'ssn' in vals.keys():
            if vals['ssn'] is not False:
                vals.update({'ssn': self.encrypt(vals['ssn'])})
        return super(VrEmployeeEncrypt, self).write(vals)

    @api.multi
    def read(self, fields=None, load='_classic_read'):
        res = super(VrEmployeeEncrypt, self).read(fields, load)
        for rec in res:
            if 'ssn' in rec.keys():
                if rec['ssn'] is not False:
                    rec.update({'ssn': self.decrypt(rec['ssn'])})
        return res

    