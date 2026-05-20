#!/bin/bash
echo 'p4' | sudo -S make clean
rm /media/sf_Project/Project/Planter/src/targets/bmv2/software/model_test/test_environment/*.p4
cp /media/sf_Project/Project/Planter/P4/DT_standard_classification_PeerRush.p4 /media/sf_Project/Project/Planter/src/targets/bmv2/software/model_test/test_environment/DT_standard_classification_PeerRush.p4
echo 'h1 /home/p4/src/p4dev-python-venv/bin/python3 /media/sf_Project/Project/Planter/src/test/test_switch_model_bmv2_software.py' | sudo -S make PYTHON_BIN=/home/p4/src/p4dev-python-venv/bin/python3 run
