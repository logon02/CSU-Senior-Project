# KeyGuardian Test Plan

## Test Plan Identifier:

I will organize each of my test cases by labeling each with “Case-01”,
“Case-02”, etc. This will ensure that each case is organized and can easily be
found or referenced in the document.

## Introduction:

This is my formal test plan document for KeyGuardian and will detail all the
cases I plan to test my software with. This plan will include system-level
testing and unit testing. All the features of this software will be tested for
accuracy and efficiency and I am going to develop a survey for testers to
provide some feedback for KeyGuardian, known as crowdsourced testing.

The goal of this test plan is to collect the necessary data from testers and
ensure that any bugs are corrected and the overall software product can be
improved. KeyGuardian is extendable software so that it can eventually allow the
user to accomplish even more tasks with one central tool. It is important to
test a product so that features are added and/or improved. My goal for
KeyGuardian is to provide users a secure and reliable way to store and generate
passwords without having to remember or write down all their passwords. This
cannot be accomplished without robust and comprehensive testing.

A main constraint is that I am the sole developer of this project and therefore
bugs may take more time to fix than if I had a development team. This software
is also an early version and is subject to many changes in the future. Any
libraries that are used are free and open source because I have chosen to not
use paid software or libraries. Another constraint is the amount of risk for
KeyGuardian. Since this is a password manager tool, there is a great risk
involved due to the sensitivity of the data stored. However, the security will
be tested extensively.

## References:

Link for the project repository: <https://github.com/logon02/CSU-Senior-Project>

Proposal document:
[Proposal.md](https://github.com/logon02/CSU-Senior-Project/blob/master/docs/Proposal.md)

Requirements document:
[KeyGuardianRequirements.docx](https://github.com/logon02/CSU-Senior-Project/blob/master/docs/Key%20Guardian%20Requirements%20-%20Ferguson.docx)

## Test Items:

-   KeyGuardian v1.0

## Features to be Tested:

-   Logging in

-   Creating user: requirement ID \#01

-   Characters slider

-   Generating passwords: requirement ID \#03

-   Password breach checker: requirement ID \#04

-   Security scale rating: requirement ID \#05

-   Storing passwords: requirement ID \#07

-   Add/remove passwords: requirement ID \#08

-   Search for password

-   GUI matches system theme: requirement ID \#10

-   Works on any OS: requirement ID \#12

-   Logout button

-   Input validation: requirement ID \#20

-   Access only with master password: requirement ID \#24

-   Encryption/decryption for passwords: requirement ID \#25

-   Password policy: requirement ID \#26

## Features Not to be Tested:

-   User-friendly messages: requirement ID \#14

    -   Reasoning: These messages are not part of the overall functionality of
        the software and are low priority.

-   No max capacity for the password database: requirement ID \#21

    -   Reasoning: There is no need to test this because the database file will
        always only be limited by the host system’s storage capacity

## Approach:

My approach to testing this software and its features is to utilize a master
test plan which will test all levels of KeyGuardian and ensure that all the
functionality included in the requirements document is complete. A majority of
the testing will be manual, involving ad hoc testing and some black-box testing
with use cases. I will also conduct some functional and usability testing by
allowing some selected testers to use the software and provide their feedback
and opinions on the software product. This kind of testing is better known as
crowdsourced testing. I also plan to run some security testing mainly due to the
sensitivity of any data that may be stored by KeyGuardian.

## Item Pass/Fail Criteria:

These are the primary questions I will use to determine whether or not a test is
successful:

-   Is the feature/product functional?

-   Does it perform as expected or required?

-   Are there any errors?

-   Was the testing sufficient?

-   Is it user-friendly?

-   Are there any risks or concerns?

If there is something that still needs to be addressed after asking these
questions, then the test case is a failure. The software must be corrected and
the feature tested again asking the same questions. As long as there are no
further issues and the questions have been addressed appropriately, then the
test will be considered a pass.

## KeyGuardian Test Cases:

Case-01:

| **Test Scenario**             | **Test Case**                   | **Test Data**                            | **Expected Result**      |
|-------------------------------|---------------------------------|------------------------------------------|--------------------------|
| Creation of user and password | Check response on creating user | Username: `testUser1` Password: `Knc815&j(e` | User Creation successful |

Case-02:

| **Test Scenario**        | **Test Case**                                | **Test Data** | **Expected Result**                |
|--------------------------|----------------------------------------------|---------------|------------------------------------|
| Test Login Functionality | Check response on leaving login fields blank | n/a           | Gives error and login unsuccessful |

Case-03:

| **Test Scenario**        | **Test Case**                                 | **Test Data**                                                                    | **Expected Result**                |
|--------------------------|-----------------------------------------------|----------------------------------------------------------------------------------|------------------------------------|
| Test Login Functionality | Check response on incorrect login credentials | Username: John Doe Password: password123 Username: Jane_Doe Password: NB\*95e}2h | Gives error and login unsuccessful |

Case-04:

| **Test Scenario**        | **Test Case**                                  | **Test Data**                            | **Expected Result** |
|--------------------------|------------------------------------------------|------------------------------------------|---------------------|
| Test Login Functionality | Check response on entering correct credentials | Username: `testUser1` Password: `Knc815&j(e` | Login Successful    |

Case-05:

| **Test Scenario**      | **Test Case**                     | **Test Data**                       | **Expected Result**                                           |
|------------------------|-----------------------------------|-------------------------------------|---------------------------------------------------------------|
| Test Characters Slider | Check response to dragging slider | Number of characters: 8, 13, 20, 32 | The slider moves and displays the number of characters chosen |

Case-06:

| **Test Scenario**        | **Test Case**                                                 | **Test Data**                        | **Expected Result**                                                |
|--------------------------|---------------------------------------------------------------|--------------------------------------|--------------------------------------------------------------------|
| Test Password Generation | Check response to choosing characters and generating password | Number of characters: 10, 15, 21, 35 | Generated password displays and is the number of characters chosen |

Case-07:

| **Test Scenario** | **Test Case**                                | **Test Data** | **Expected Result**                                     |
|-------------------|----------------------------------------------|---------------|---------------------------------------------------------|
| Test Copy Button  | Check response when clicking the copy button | n/a           | The button copies the current password to the clipboard |

Case-08:

| **Test Scenario**   | **Test Case**                              | **Test Data**                                                         | **Expected Result**                                 |
|---------------------|--------------------------------------------|-----------------------------------------------------------------------|-----------------------------------------------------|
| Test Breach Checker | Check response when a password is searched | password123 N745grtIj\@M ilikepie oMj\|F"C28S\$] tkF\$V?2QT;%8:,ZCyxb | Displays if the password has been leaked previously |

Case-09:

| **Test Scenario**   | **Test Case**                             | **Test Data**                                                         | **Expected Result**                      |
|---------------------|-------------------------------------------|-----------------------------------------------------------------------|------------------------------------------|
| Test Security Scale | Check response when a password is entered | password123 N745grtIj\@M ilikepie oMj\|F"C28S\$] tkF\$V?2QT;%8:,ZCyxb | Password is rated on a color-coded scale |

Case-10:

| **Test Scenario**     | **Test Case**                                           | **Test Data**                                                                                                        | **Expected Result**                      |
|-----------------------|---------------------------------------------------------|----------------------------------------------------------------------------------------------------------------------|------------------------------------------|
| Test Adding Passwords | Check response when a password is added to the database | Website: Google Username: jackSims Password: u&8Q-phY2a Website: Github Username: codingMaster Password: H\$2f3i}VU- | Password is stored to the local database |

Case-11:

| **Test Scenario**       | **Test Case**                             | **Test Data**                                                   | **Expected Result**                   |
|-------------------------|-------------------------------------------|-----------------------------------------------------------------|---------------------------------------|
| Test Removing Passwords | Check response when a password is removed | Remove: Website: Google Username: jackSims Password: u&8Q-phY2a | Password is removed from the database |

Case-12:

| **Test Scenario**           | **Test Case**                              | **Test Data**             | **Expected Result**                     |
|-----------------------------|--------------------------------------------|---------------------------|-----------------------------------------|
| Test Searching for Password | Check response when a password is searched | Search for: Github, Canva | Password is displayed when searched for |

Case-13:

| **Test Scenario** | **Test Case**                                       | **Test Data** | **Expected Result**             |
|-------------------|-----------------------------------------------------|---------------|---------------------------------|
| Test GUI Theme    | Check response when system theme is light/dark mode | n/a           | GUI matches system chosen theme |

Case-14:

| **Test Scenario**                             | **Test Case**                           | **Test Data** | **Expected Result**             |
|-----------------------------------------------|-----------------------------------------|---------------|---------------------------------|
| Test KeyGuardian on Windows, Linux, and MacOS | Check response when run on different OS | n/a           | Software runs on each OS tested |

Case-15:

| **Test Scenario**  | **Test Case**                                | **Test Data** | **Expected Result**                                  |
|--------------------|----------------------------------------------|---------------|------------------------------------------------------|
| Test Logout Button | Check response when logout button is clicked | n/a           | User is logged out and confirmation message displays |

Case-16:

| **Test Scenario**                    | **Test Case**                                  | **Test Data** | **Expected Result**                                               |
|--------------------------------------|------------------------------------------------|---------------|-------------------------------------------------------------------|
| Test Input Validation for All Fields | Check response when unexpected data is entered |               | Software catches any errors and continues when input is corrected |

Case-17:

| **Test Scenario**    | **Test Case**                                             | **Test Data**                          | **Expected Result**                            |
|----------------------|-----------------------------------------------------------|----------------------------------------|------------------------------------------------|
| Test Master Password | Check response for incorrect password and master password | Incorrect password: KeyGuardian123\@nh | Access is granted only through master password |

Case-18:

| **Test Scenario**        | **Test Case**                                 | **Test Data** | **Expected Result**                                            |
|--------------------------|-----------------------------------------------|---------------|----------------------------------------------------------------|
| Test Database Encryption | Check response when logged out for first time | n/a           | Database is fully encrypted when the software is not logged in |

Case-19:

| **Test Scenario**        | **Test Case**                         | **Test Data** | **Expected Result**                               |
|--------------------------|---------------------------------------|---------------|---------------------------------------------------|
| Test Database Decryption | Check response when user is logged in | n/a           | Database is decrypted and passwords can be viewed |

Case-20:

| **Test Scenario**                   | **Test Case**                      | **Test Data** | **Expected Result**                     |
|-------------------------------------|------------------------------------|---------------|-----------------------------------------|
| Test Password Policy Minimum Length | Check required length of passwords | n/a           | Minimum length is at least 8 characters |

Case-21:

| **Test Scenario**                      | **Test Case**                                  | **Test Data** | **Expected Result**                      |
|----------------------------------------|------------------------------------------------|---------------|------------------------------------------|
| Test Password Policy Uppercase Letters | Check the required amount of uppercase letters | n/a           | Minimum amount of uppercase letters is 2 |

Case-22:

| **Test Scenario**            | **Test Case**                    | **Test Data** | **Expected Result**            |
|------------------------------|----------------------------------|---------------|--------------------------------|
| Test Password Policy Numbers | Check required amount of numbers | n/a           | Minimum amount of numbers is 2 |

Case-23:

| **Test Scenario**                       | **Test Case**                               | **Test Data** | **Expected Result**                       |
|-----------------------------------------|---------------------------------------------|---------------|-------------------------------------------|
| Test Password Policy Special Characters | Check required amount of special characters | n/a           | Minimum amount of special characters is 2 |

Case-24:

| **Test Scenario**                    | **Test Case**                 | **Test Data** | **Expected Result**                  |
|--------------------------------------|-------------------------------|---------------|--------------------------------------|
| Test Password Policy Bits of Entropy | Check desired bits of entropy | n/a           | Desired amount of entropy is 85 bits |

## Suspension Criteria and Resumption Requirements:

There are no suspension criteria for the testing of this software due to
continuous testing and ad hoc tests. Furthermore, participants in crowd-source
testing are at any time completely free to stop testing and withdraw from the
project.

## Test Deliverables:

-   KeyGuardian Test Plan

-   Testing Report

## Test Environment:

The testing environment will be on my laptop with no network connection
required. The purpose of the software is to be completely local to a system, so
no internet will ever be required to use KeyGuardian. I am going to provide my
laptop to each tester and allow them to use the software for a period of time
and to provide their feedback.

## Estimate:

There are no monetary costs involved for the development or testing of the
project and every library/tool I am using is free and open source.

## Schedule:

Testing milestones:

-   Test Plan Completed: 11/20/2023

-   Ad hoc tests: 11/27/2023

-   Initial Soft Tests: 01/08 – 01/22/2024

-   Black-box Testing: 01/22/2024

-   Crowdsourcing Tests: 01/29 – 02/12/2024

-   Tester Feedback: 02/19

-   Bug Fixes Applied: NLT 03/11/2024

-   Functionality or Feature Updates: 04/08/2024

-   Final Test Report: 03/18/2024

## Responsibilities:

Developer & Project Manager (Myself):

-   As the project manager, I am responsible for planning and organizing the
    testing of the project

-   I am responsible for all documentation

-   As the sole developer, I am also responsible for designing and implementing
    any software updates or features

## Risks:

-   Myself as the sole developer and tester

-   Changes in requirements or priority

-   Changes in project scope

-   Sensitivity of password management

-   Collection of testing data

-   Testing environment configuration

## Assumptions and Dependencies:

Software assumptions:

-   I will have 8-12 testers

-   Each tester will provide feedback

-   The scope and project requirements will remain stable

-   The testing environment (my laptop) will be available to all testers

-   Each tester will create their own master password

-   Encryption will provide data security

>   Software dependencies:

-   Requirements documentation

-   Complete software testing

-   Fernet encryption library

-   Custom Tkinter library for GUI

-   PasswordPolicy library

-   Sqlite3 library for database connections

-   Pyperclip library

-   Bcrypt for hashing and salting

## Crowd-Source Testing Script:

### Introduction:

Welcome! I am Logan Ferguson, a Cybersecurity student at Charleston Southern
University, and I am running some tests for my senior project. I have developed
a password manager and generator called KeyGuardian and am thrilled to offer you
the chance to participate in testing my software!

### Overview:

KeyGuardian is a password generator, checker, and manager of passwords that are
stored securely on a local system. This software allows the user to choose the
length of a password and to generate a secure password using upper and lower
case letters, numbers, and symbols. KeyGuardian will check any current passwords
the user may have to see if it is secure and whether or not it has been exposed
in a previous data breach. The security of passwords will be checked and rated
on a scale, and a friendly message will prompt a description of the security
rating. Lastly, the user will be able to store passwords in a local database
that will be encrypted with a master key, which is generated by KeyGuardian.
This will be the only password that users will need to keep in a safe place to
unlock the rest of their passwords. The purpose of this software is not to just
create, check, and store passwords securely, but to educate users on how to
better protect their online accounts.

### Testing Purpose:

You may be thinking why I am asking for your help. Well, the reason is that my
project has entered the critical stage of testing that requires user feedback. I
need your help to test my software’s functionality, security, and its overall
user-friendliness. Your feedback and opinions are important!

### Testing Scenario:

Imagine you are trying to create a new Google account and you have just entered
an email address and the site is now asking for a password. Instead of coming up
with a password and remembering it or even writing it down, you have just
installed a new password manager called KeyGuardian and you want to try it out.
Create your KeyGuardian master password and use the software to generate a
secure password for you new Google account.

You now can store this password and username and you only need one master
password to access them! KeyGuardian can be used to generate and store passwords
for every online account. It can also check your current or even new passwords
you wish to use and determine if they have been exposed in a previous data leak.

Try generating a password and check if it has been breached. Come up with a
random password that you think has been exposed before and try it. Generate and
add any accounts you want to the database! Try searching for a password then try
removing one. Also, try logging out and back in again. It would be helpful if
you could test every feature you can to ensure my software is fully functional.

### Tester Feedback:

If you have any questions, feel free to let me know at any time during testing!
To provide your feedback, please use the link below and answer the questions.

Feedback form: <https://forms.gle/d6vBi57NoqwHBSB67>

Thank you so much for participating in this test and contributing with your
feedback!
