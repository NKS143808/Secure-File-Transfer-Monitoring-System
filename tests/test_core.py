import tempfile,unittest
from pathlib import Path
from src.integrity import sha256_file
from src.policy import sensitive,allowed
class CoreTests(unittest.TestCase):
 def test_hash_changes(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)/"x.txt";p.write_text("a");h=sha256_file(p);p.write_text("b");self.assertNotEqual(h,sha256_file(p))
 def test_sensitive(self):self.assertTrue(sensitive("secret.key"))
 def test_allowed(self):
  with tempfile.TemporaryDirectory() as d:
   base=Path(d);child=base/"sub"/"x";child.parent.mkdir();self.assertTrue(allowed(str(child),[str(base)]));self.assertFalse(allowed(str(child),[str(base/"other")]))
if __name__=="__main__":unittest.main()
