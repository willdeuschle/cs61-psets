CS 61 Problem Set 6
===================

**Fill out both this file and `AUTHORS.md` before submitting.** We grade
anonymously, so put all personally identifying information in `AUTHORS.md`.

Race conditions
---------------
Write a SHORT paragraph here explaining your strategy for avoiding
race conditions. No more than 400 words please.
We had three pieces of functionality with potential with race conditions, thus we had
three code areas requiring synchronization, which each required its own mutex.
These three areas included access to our connections table (requiring only a simple mutex),
a flag for indicating when the most recent thread successfully received the first
response from the server (which required a mutex and a condition variable, which
was used to notify the main thread when it should create the next thread), and
sending messages to the server (which required a simple mutex). This last part
was necessary so that we didn't hit the server with messages when we should have
been resting.



Grading notes (if any)
----------------------



Extra credit attempted (if any)
-------------------------------
