Implementation of a file sharing protocol which has functionalities like download and upload files, and indexed searching.

The following steps are required in order to test the commands:

1. Extract the folder 20171017_20171202_20171204_Project2 from the Zip Folder

2. Go to system_1, and open a terminal window from this folder

3. Go to system_2, and open another terminal window from this folder

4. From the system_1 terminal window, run the command:
    $ python2 s1_trial.py
   From the system_2 terminal window, run the command:
    $ python2 s2_trial.py
    This connects the two servers.

5. Now you get a prompt "$>" to test the commands on both the terminals

6. To test IndexGet shortlist:
```
    $> IndexGet shortlist 1580000000 1590000000
    For the bonus part:
    $> IndexGet shortlist 1580000000 1590000000 *.pdf
    $> IndexGet shortlist 1580000000 1590000000 *.txt
```
7. To test IndexGet longlist:
```
    $> IndexGet longlist 
    For the bonus part:
    $> IndexGet longlist Programmer
    $> IndexGet longlist xa
```
8. To test FileHash verify
```
    $> FileHash verify a.txt
```
9. To test FileHash checkall
```
    $> FileHash checkall
```
10. To test FileDownload TCP
```
    $> FileDownload TCP 2.txt
```
11. To test FileDownload UDP
```
    $> FileDownload UDP 3.txt
```
12. To test Cache verify
```
    $> Cache verify a.txt
```
13. To test Cache show
```
    $> Cache show 
```
