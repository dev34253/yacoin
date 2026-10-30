// Copyright (c) 2012-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "random.h"
#include "scheduler.h"

#include "test/test_bitcoin.h"

#include <boost/bind.hpp>
#include <boost/thread.hpp>
#include <boost/test/unit_test.hpp>

#include <future>

BOOST_AUTO_TEST_SUITE(scheduler_tests)

static void microTask(CScheduler& s, boost::mutex& mutex, int& counter, int delta, boost::chrono::system_clock::time_point rescheduleTime)
{
    {
        boost::unique_lock<boost::mutex> lock(mutex);
        counter += delta;
    }
    boost::chrono::system_clock::time_point noTime = boost::chrono::system_clock::time_point::min();
    if (rescheduleTime != noTime) {
        CScheduler::Function f = boost::bind(&microTask, boost::ref(s), boost::ref(mutex), boost::ref(counter), -delta + 1, noTime);
        s.schedule(f, rescheduleTime);
    }
}

static void MicroSleep(uint64_t n)
{
#if defined(HAVE_WORKING_BOOST_SLEEP_FOR)
    boost::this_thread::sleep_for(boost::chrono::microseconds(n));
#elif defined(HAVE_WORKING_BOOST_SLEEP)
    boost::this_thread::sleep(boost::posix_time::microseconds(n));
#else
    //should never get here
    #error missing boost sleep implementation
#endif
}

BOOST_AUTO_TEST_CASE(manythreads)
{
    // Stress test: hundreds of microsecond-scheduled tasks,
    // serviced by 10 threads.
    //
    // So... ten shared counters, which if all the tasks execute
    // properly will sum to the number of tasks done.
    // Each task adds or subtracts a random amount from one of the
    // counters, and then schedules another task 0-1000
    // microseconds in the future to subtract or add from
    // the counter -random_amount+1, so in the end the shared
    // counters should sum to the number of initial tasks performed.
    CScheduler microTasks;

    boost::mutex counterMutex[10];
    int counter[10] = { 0 };
    FastRandomContext rng(42);
    auto zeroToNine = [](FastRandomContext& rc) -> int { return rc.randrange(10); }; // [0, 9]
    auto randomMsec = [](FastRandomContext& rc) -> int { return -11 + rc.randrange(1012); }; // [-11, 1000]
    auto randomDelta = [](FastRandomContext& rc) -> int { return -1000 + rc.randrange(2001); }; // [-1000, 1000]

    boost::chrono::system_clock::time_point start = boost::chrono::system_clock::now();
    boost::chrono::system_clock::time_point now = start;
    boost::chrono::system_clock::time_point first, last;
    size_t nTasks = microTasks.getQueueInfo(first, last);
    BOOST_CHECK(nTasks == 0);

    for (int i = 0; i < 100; i++) {
        boost::chrono::system_clock::time_point t = now + boost::chrono::microseconds(randomMsec(rng));
        boost::chrono::system_clock::time_point tReschedule = now + boost::chrono::microseconds(500 + randomMsec(rng));
        int whichCounter = zeroToNine(rng);
        CScheduler::Function f = boost::bind(&microTask, boost::ref(microTasks),
                                             boost::ref(counterMutex[whichCounter]), boost::ref(counter[whichCounter]),
                                             randomDelta(rng), tReschedule);
        microTasks.schedule(f, t);
    }
    nTasks = microTasks.getQueueInfo(first, last);
    BOOST_CHECK(nTasks == 100);
    BOOST_CHECK(first < last);
    BOOST_CHECK(last > now);

    // As soon as these are created they will start running and servicing the queue
    boost::thread_group microThreads;
    for (int i = 0; i < 5; i++)
        microThreads.create_thread(boost::bind(&CScheduler::serviceQueue, &microTasks));

    MicroSleep(600);
    now = boost::chrono::system_clock::now();

    // More threads and more tasks:
    for (int i = 0; i < 5; i++)
        microThreads.create_thread(boost::bind(&CScheduler::serviceQueue, &microTasks));
    for (int i = 0; i < 100; i++) {
        boost::chrono::system_clock::time_point t = now + boost::chrono::microseconds(randomMsec(rng));
        boost::chrono::system_clock::time_point tReschedule = now + boost::chrono::microseconds(500 + randomMsec(rng));
        int whichCounter = zeroToNine(rng);
        CScheduler::Function f = boost::bind(&microTask, boost::ref(microTasks),
                                             boost::ref(counterMutex[whichCounter]), boost::ref(counter[whichCounter]),
                                             randomDelta(rng), tReschedule);
        microTasks.schedule(f, t);
    }

    // Drain the task queue then exit threads
    microTasks.stop(true);
    microThreads.join_all(); // ... wait until all the threads are done

    int counterSum = 0;
    for (int i = 0; i < 10; i++) {
        BOOST_CHECK(counter[i] != 0);
        counterSum += counter[i];
    }
    BOOST_CHECK_EQUAL(counterSum, 200);
}

BOOST_AUTO_TEST_CASE(idle_thread_runs_a_later_task)
{
    // A service thread started on an empty queue takes the idle branch (it
    // releases the lock while it adds entropy, then waits unless a task has
    // arrived), runs a task scheduled after it started, and stops.
    CScheduler scheduler;
    boost::thread service(boost::bind(&CScheduler::serviceQueue, &scheduler));
    // serviceQueue holds the scheduler's lock from counting itself until it
    // has found the queue empty, so once it is counted it is in the idle
    // branch, and the task below is scheduled only after that.
    while (!scheduler.AreThreadsServicingQueue()) {
        boost::this_thread::yield();
    }
    std::promise<void> ran;
    scheduler.schedule([&ran] { ran.set_value(); });
    ran.get_future().wait();
    scheduler.stop();
    service.join();
    BOOST_CHECK(!scheduler.AreThreadsServicingQueue());
}

BOOST_AUTO_TEST_CASE(idle_thread_ends_when_interrupted)
{
    // A service thread on an empty queue waits for a task; the wait is a
    // boost interruption point, so interrupting the thread (as the node's
    // shutdown does with its thread group) ends it, and it is no longer
    // counted. Nothing before the wait is an interruption point, so
    // interrupting at once still ends the thread in the wait, after the idle
    // branch.
    CScheduler scheduler;
    boost::thread service(boost::bind(&CScheduler::serviceQueue, &scheduler));
    service.interrupt();
    service.join();
    BOOST_CHECK(!scheduler.AreThreadsServicingQueue());
}

BOOST_AUTO_TEST_SUITE_END()
