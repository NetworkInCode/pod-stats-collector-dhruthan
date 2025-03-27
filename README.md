[![Review Assignment Due Date](https://classroom.github.com/assets/deadline-readme-button-22041afd0340ce965d47ae6ef1cefeee28c7c493a6346c4f15d667ab976d596c.svg)](https://classroom.github.com/a/KpvttnVe)
# pod-stats

Objective
---------

Write a simple eBPF-based stats collector for a kubernetes cluster. Some of the sample stats could be:

- Files opened by the pod
- Memory usage of the pod in real time
- Any container-level stats that you think could be useful
- ......
  
The stats list is intentionally open-ended. You can add as many to the list as you would like :)

The tool should be run on-demand basis and provide current stats when invoked. 

Repository Setup
----------------

1. Clone the repository
```
git clone <>
cd pod-stats
```
2. Modify and extend the provided template according to the requirements.
3. Also upload a screen recording and/or detailed screenshots (with captions) of the tool running on your system.

Implementation Details
----------------------

1. Use eBPF to track pod activity.
2. Collect stats like number of open files, memory usage etc.
3. The user-space control program can be implemented using libbpf, BCC or Go eBPF.
4. Provide logging for debugging and verification

Judgement Criteria
-------------------

Expected test environment for qualifcation: A kubernetes cluster with one node and at least one pod running. 
The tool should connect to the k8s cluster and fetch all stats from the running pod. If there is more than one pod running, the tool should spew out stats for all pods in a neat format.

The code will be judged based on the following aspects:

- Architecture of the eBPF program
- How optimised is the logic for fetching per-pod details in eBPF.
- Utility of the stats collected
- Any real-time use cases that can be demonstrated for the stats collected
- Any use cases for the collected stats that can be of significant value with future extensions.
- Documentation of the implementation and code structure

Repository Structure
--------------------

```
/ (Root)
│── README.md          # Detailed assignment instructions
│── Makefile           # Build and run commands
│── src/
│   │── main.c         # User-space control program
│   │── bpf_prog.c     # eBPF program to get pod stats
│── scripts/
│   │── test.sh        # Script to test the program
|── testing
|   |── README.md      # Details of the implementation, test environment and test cases covered, stats collected, including a brief on how each one could be of significance
```

PLEASE NOTE: The repository serves only as a starter template and is flexible to modifications. It could be extended with additional files/folders as appropriate and even based on the library that is chosen for implementation. Just ensure the there is a test script and a detailed documentation of what each file does.


Submission Instructions
------------------------

1. Complete your implementation and ensure it meets the assignment requirements.
2. Update the README.md with detailed instructions on how to build and run your solution.
3. Make a pull request (PR) to submit your final code.
4. Your PR should include:
   - A description of your implementation.
   - Any limitations or known issues.
   - Example test cases
