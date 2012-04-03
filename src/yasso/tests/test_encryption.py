
from base64 import urlsafe_b64encode
import os
import shutil
import tempfile

try:
    import unittest2 as unittest
except ImportError:
    import unittest


class TestKeyWriter(unittest.TestCase):

    def setUp(self):
        self.dirpath = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.dirpath)

    def _class(self):
        from yasso.encryption import KeyWriter
        return KeyWriter

    def _make(self, *args, **kw):
        return self._class()(*args, **kw)

    def _make_default(self, **kw):
        return self._make(self.dirpath, **kw)

    def test_get_fresh_key_first_time(self):
        obj = self._make_default()
        key_id, key = obj.get_fresh_key()
        self.assertIsInstance(key_id, bytes)
        self.assertEqual(len(key_id), 6)
        self.assertEqual(len(key), 64)
        self.assertIsInstance(key, bytes)
        f = open(os.path.join(self.dirpath, key_id.decode('ascii')))
        stored_key = f.read()
        f.close()
        self.assertEqual(key, stored_key)

    def test_get_fresh_key_second_time_matches_first(self):
        obj = self._make_default()
        key_id1, key1 = obj.get_fresh_key()
        key_id2, key2 = obj.get_fresh_key()
        self.assertEqual(key_id1, key_id2)
        self.assertEqual(key1, key2)

    def test_get_fresh_key_after_freshness_expired(self):
        obj = self._make_default(freshness=0)
        key_id1, key1 = obj.get_fresh_key()
        key_id2, key2 = obj.get_fresh_key()
        self.assertNotEqual(key_id1, key_id2)
        self.assertNotEqual(key1, key2)

    def test_prune(self):
        obj = self._make_default(timeout=0)
        self.assertEqual(os.listdir(self.dirpath), [])
        key_id, _key = obj.get_fresh_key()
        self.assertEqual(os.listdir(self.dirpath), [key_id.decode('ascii')])
        f = open(os.path.join(self.dirpath, '.hidden-file'), 'w')
        f.write(b'x')
        f.close()
        obj._prune()
        self.assertEqual(os.listdir(self.dirpath), ['.hidden-file'])


class TestKeyReader(unittest.TestCase):

    def setUp(self):
        self.dirpath = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.dirpath)

    def _class(self):
        from yasso.encryption import KeyReader
        return KeyReader

    def _make(self, *args, **kw):
        return self._class()(*args, **kw)

    def _make_default(self, **kw):
        return self._make(self.dirpath, **kw)

    def test_get_key_with_unicode(self):
        obj = self._make_default()
        with self.assertRaises(TypeError):
            obj.get_key(u"spam")

    def test_get_key_when_key_id_starts_with_dot(self):
        obj = self._make_default()
        with self.assertRaises(KeyError):
            obj.get_key(b'.spam')

    def test_get_key_when_key_id_contains_slash(self):
        obj = self._make_default()
        with self.assertRaises(KeyError):
            obj.get_key(b'spam/eggs')

    def test_get_key_when_key_id_contains_backslash(self):
        obj = self._make_default()
        with self.assertRaises(KeyError):
            obj.get_key(b'spam\\eggs')

    def test_get_key_when_key_id_does_not_exist(self):
        obj = self._make_default()
        with self.assertRaises(KeyError):
            obj.get_key(b'spam')

    def test_get_key_when_key_id_is_old(self):
        obj = self._make_default(timeout=0)
        f = open(os.path.join(self.dirpath, 'mykey'), 'w')
        f.write(b'x' * 64)
        f.close()
        with self.assertRaises(KeyError):
            obj.get_key(b'mykey')

    def test_get_key_when_key_id_is_fresh(self):
        obj = self._make_default()
        f = open(os.path.join(self.dirpath, 'mykey'), 'w')
        f.write(b'x' * 64)
        f.close()
        key = obj.get_key(b'mykey')
        self.assertEqual(key, b'x' * 64)

    def test_get_key_from_cache_when_key_id_is_fresh(self):
        obj = self._make_default()
        f = open(os.path.join(self.dirpath, 'mykey'), 'w')
        f.write(b'x' * 64)
        f.close()
        key1 = obj.get_key(b'mykey')
        key2 = obj.get_key(b'mykey')
        self.assertEqual(key1, b'x' * 64)
        self.assertEqual(key2, b'x' * 64)

    def test_get_key_from_cache_when_key_id_is_old(self):
        obj = self._make_default()
        f = open(os.path.join(self.dirpath, 'mykey'), 'w')
        f.write(b'x' * 64)
        f.close()
        obj.get_key(b'mykey')
        obj.timeout = 0
        with self.assertRaises(KeyError):
            obj.get_key(b'mykey')
        self.assertFalse(obj.keys)


class TestEncryptionAndDecryption(unittest.TestCase):

    def setUp(self):
        self.dirpath = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.dirpath)

    def _make_encryptor(self):
        from yasso.encryption import Encryptor
        from yasso.encryption import KeyWriter
        key_writer = KeyWriter(self.dirpath)
        return Encryptor(key_writer)

    def _make_decryptor(self):
        from yasso.encryption import Decryptor
        from yasso.encryption import KeyReader
        key_reader = KeyReader(self.dirpath)
        return Decryptor(key_reader)

    def test_encrypt_and_decrypt_success(self):
        enc = self._make_encryptor()
        ciphertext = enc({'message': 'Hello, world!'})
        self.assertIsInstance(ciphertext, unicode)
        dec = self._make_decryptor()
        data = dec(ciphertext)
        self.assertEqual(data, {'message': 'Hello, world!'})

        # Encrypting again should not produce the same ciphertext.
        ciphertext2 = enc({'message': 'Hello, world!'})
        self.assertNotEqual(ciphertext, ciphertext2)

    def test_decrypt_wrong_format(self):
        dec = self._make_decryptor()
        from yasso.encryption import DecryptionError
        with self.assertRaises(DecryptionError):
            dec('BBBB')

    def test_decrypt_missing_key_id(self):
        dec = self._make_decryptor()
        from yasso.encryption import DecryptionError
        with self.assertRaises(DecryptionError):
            dec(urlsafe_b64encode(b'\0spam'))

    def test_decrypt_with_signature_mismatch(self):
        enc = self._make_encryptor()
        dec = self._make_decryptor()
        ciphertext = enc({'message': 'Hello, world!'})
        data = dec.b64decode(ciphertext)
        data = data[:-1] + bytes([ord(data[-1]) ^ 16])
        broken_ciphertext = urlsafe_b64encode(data)
        from yasso.encryption import DecryptionError
        with self.assertRaises(DecryptionError):
            dec(broken_ciphertext)
