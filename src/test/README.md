### Compiling/running unit tests

Unit tests will be automatically compiled if dependencies were met in `./configure`
and tests weren't explicitly disabled.

After configuring, they can be run with `make check`.

To run the bitcoind tests manually, launch `src/test/test_bitcoin`.

To add more bitcoind tests, add `BOOST_AUTO_TEST_CASE` functions to the existing
.cpp files in the `test/` directory or add new .cpp files that
implement new BOOST_AUTO_TEST_SUITE sections.

To run the bitcoin-qt tests manually, launch `src/qt/test/test_bitcoin-qt`

To add more bitcoin-qt tests, add them to the `src/qt/test/` directory and
the `src/qt/test/test_main.cpp` file.

### Running individual tests

test_bitcoin has some built-in command-line arguments; for
example, to run just the getarg_tests verbosely:

    test_bitcoin --log_level=all --run_test=getarg_tests

... or to run just the doubledash test:

    test_bitcoin --run_test=getarg_tests/doubledash

Run `test_bitcoin --help` for the full list.

### Known defects

A test that pins a known defect uses the known-failure checks of `known_failure.h` instead of asserting today's wrong value.
`KNOWN_FAILURE_EQUAL(row, actual, correct, current)` compares a value with the correct one and with today's;
`KNOWN_FAILURE(row, actual, correct, current)` takes the correct and today's conditions and shows `actual`. Both pass only while the outcome is
today's; once the correct behaviour holds they fail with "<row> no longer fails; remove the known-failure check", so the fix replaces the check with a
plain assertion, and any other outcome fails as "not the expected known failure". New checks name the defect's row in the modernisation gap register,
e.g. `"MG-045"`. Behaviour that is intended is asserted with plain checks. The functional tests have the same check, `known_failure()` in
`test/functional/test_framework/util.py`. `known_failure_tests` checks the reporting with four deliberate failures, so a run's summary says "(4
failures are expected)"; any other failure still fails the run.

### Note on adding test cases

The sources in this directory are unit test cases.  Boost includes a
unit testing framework, and since bitcoin already uses boost, it makes
sense to simply use this framework rather than require developers to
configure some other framework (we want as few impediments to creating
unit tests as possible).

The build system is setup to compile an executable called `test_bitcoin`
that runs all of the unit tests.  The main source file is called
test_bitcoin.cpp. To add a new unit test file to our test suite you need 
to add the file to `src/Makefile.test.include`. The pattern is to create 
one test file for each class or source file for which you want to create 
unit tests.  The file naming convention is `<source_filename>_tests.cpp` 
and such files should wrap their tests in a test suite 
called `<source_filename>_tests`. For an example of this pattern, 
examine `uint256_tests.cpp`.

For further reading, I found the following website to be helpful in
explaining how the boost unit test framework works:
[http://www.alittlemadness.com/2009/03/31/c-unit-testing-with-boosttest/](http://www.alittlemadness.com/2009/03/31/c-unit-testing-with-boosttest/).
