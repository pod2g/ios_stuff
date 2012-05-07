#!/bin/bash
javac Main.java
jar cvmf MANIFEST.MF tsc.jar Main.class
rm Main.class
