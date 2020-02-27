# ghidra-scripts
A suite of Ghidra scripts to reason about binaries.

## Prerequisite
To be able to import the current project successfully into Eclipse, you first need to install [Ghidra](https://ghidra-sre.org/) (> v9.1) and set up the Eclipse classpath variable `GHIDRA_HOME` to the root folder where you have installed Ghidra. Setting the classpath variable in Eclipse can be done through the `Preferences` panel: Java > Build Path > Classpath Variables.

## Ghidra Scripts
Ghidra assumes that all custom scripts are defined within the default package. Therefore, for Ghidra to be able to detect your script, you need to place your script file in the default package.

## Project Structure
The current project contains a `resources/sample-binaries` folder containing multiple sample binaries for demonstration. Another folder `resources/tmp` is used as a temporary directory to store temporarily created projects and log files.

## Headless Run/Debug
To be able to run/debug in Headless mode, you can use the following sample command to pass it to the analyzeHeadless command in the run/debug dialog:

```
{TEMP DIRECTORY NAME} {TEMP PROJECT NAME} -import {PATH TO BINARY FILE} -deleteProject -log {PATH TO TEMP GHIDRA LOG FILE} -scriptlog {PATH TO TEMP SCRIPT LOG FILE} -scriptPath {PATH TO DIRECTORY CONTAINING THE SCRIPT} -postScript {SCRIPT FILE NAME}.java {SPACE SEPARATED ARGUMENTS TO SCRIPT}
```

Sample parameters passed to analyzeHeadless command:

```
resources/tmp/ temp-project -import resources/sample-binaries/e1 -deleteProject -log resources/tmp/ghidra.log -scriptlog resources/tmp/script.log -scriptPath src/ -postScript PCodeExtractorScript.java 123
```

