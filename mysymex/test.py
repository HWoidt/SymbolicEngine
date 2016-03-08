#!/usr/bin/env python3
# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4

import unittest
import os
import os.path
import symrun

class TestAssembly(unittest.TestCase):
    def setUp(self):
        """
        This is run before each and every test_* function
        """
        self.ofile_prefix = "./test/state_unholy"

    def test_unholy(self):
        """
        do test
        """
        symrun.main("<self>", "./test/test_unholy.asm", self.ofile_prefix)

        self.assertTrue(os.path.isfile(self.ofile_prefix+".pickle"))
        self.assertTrue(os.path.isfile(self.ofile_prefix+".yaml"))

    def tearDown(self):
        """
        This is run after each and every test_* function
        """
        os.remove(self.ofile_prefix+".pickle")
        os.remove(self.ofile_prefix+".yaml")



if __name__ == "__main__":
    unittest.main()
