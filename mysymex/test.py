#!/usr/bin/env python3
# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4

import unittest
import os
import os.path
import tempfile
import symrun

class TestAssembly(unittest.TestCase):
    def setUp(self):
        """
        This is run before each and every test_* function
        """
        self.tmpdir = tempfile.mkdtemp()
        self.ofile_prefix = os.path.join(self.tmpdir, "state_unholy")

    def test_unholy(self):
        """
        do test
        """
        cpu = symrun.main("<self>", "./test/test_unholy.asm", self.ofile_prefix, "ho")

        self.assertEqual(cpu.hash_state(), "b9949538becb9df59380a49480e81ed8679d4096")
        self.assertTrue(os.path.isfile(self.ofile_prefix+".pickle"))
        self.assertTrue(os.path.isfile(self.ofile_prefix+".yaml"))

        restoredCPU = symrun.CPU.load_state(self.ofile_prefix+".pickle")
        

    def tearDown(self):
        """
        This is run after each and every test_* function
        """
        os.remove(self.ofile_prefix+".pickle")
        os.remove(self.ofile_prefix+".yaml")
        os.rmdir(self.tmpdir)



if __name__ == "__main__":
    unittest.main()
