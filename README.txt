1. Introduction
This project presents a robust, end-to-end machine learning framework for network intrusion detection, as detailed in the dissertation "A Robust Machine Learning Framework for Network Intrusion Detection Using Behavioural Analysis."

The framework addresses the limitations of traditional signature-based systems by using a Random Forest classifier to identify malicious network traffic based on its behavioural characteristics. The project encompasses the entire data science lifecycle, from handling a large-scale dataset to training, rigorously validating, and deploying the models into a functional, real-time capable prototype.

The repository contains the following key files:

IDS_Model.ipynb: A Jupyter Notebook containing the complete Python code for data preparation, exploratory data analysis (EDA), model training, and evaluation for both binary and multi-class classifiers. This is the primary research and experimentation file.

app.py: A Flask web application that serves as a proof-of-concept prototype. It loads the trained models and provides a user interface for real-time network flow classification.

Test_app.py: A comprehensive unit test suite using the pytest framework to validate the functionality, error handling, and logical integrity of the app.py prototype.

Requirements.txt: A list of all the necessary Python libraries required to run both the modeling notebook and the Flask application.

Architecture.drawio: A diagram illustrating the complete system architecture, detailing the offline training and online inference phases of the project.

2. Link for the Dataset
This project utilizes the CSE-CIC-IDS2018 dataset, a comprehensive and realistic benchmark for intrusion detection research. It was created by the Canadian Institute for Cybersecurity (CIC).

The dataset can be downloaded from its official source:
https://www.unb.ca/cic/datasets/ids-2018.html

3. How It Works
The project is divided into two distinct phases, as illustrated in the architecture diagram:

Offline Training Phase (IDS_Model.ipynb):

The large CSE-CIC-IDS2018 dataset is processed using a memory-safe pipeline.

The data is cleaned, preprocessed, and a 10% stratified sample is created.

Two Random Forest models are trained on this data:

A Binary Classifier to distinguish between 'Benign' and 'Attack' traffic.

A Multi-Class Classifier to identify specific attack types (e.g., 'DoS-Hulk', 'Botnet').

The trained models, scalers, and label encoders are saved as .joblib files.

Online Inference Phase (app.py):

The Flask web application loads the saved .joblib artifacts into memory on start-up.

It presents a web interface where a user can paste a raw, comma-separated network flow vector.

The user can select the analysis mode: a fast "Binary Scan" or a "Detailed Threat Analysis."

The application pre-processes the input vector using the saved scaler and feeds it to the selected model.

The model returns a prediction, which is then decoded (if multi-class) and displayed to the user along with a confidence score and the top contributing features for the verdict.

4. How to Run This Code
To run this project, you will need Python 3.9+ and the required libraries.

Step 1: Set Up the Environment

First, install all the necessary Python packages using the Requirements.txt file. Open a terminal in the project directory and run:

pip install -r Requirements.txt

Step 2: Run the Model Training Notebook

If you wish to retrain the models or replicate the research findings, you can run the IDS_Model.ipynb notebook in a Jupyter environment. This will regenerate the .joblib files. Note that this requires the full dataset to be downloaded and placed in a folder named IDS2018_Data/.

Step 3: Run the Flask Prototype

To run the interactive web application, execute the app.py script from your terminal:

python app.py

Once the server is running, open a web browser and navigate to the address shown in the terminal (usually http://127.0.0.1:5000 or your local network IP).

Step 4: Run the Unit Tests

To verify the integrity and functionality of the Flask application, run the test suite using pytest:

python -m pytest

5. What You Will Get

By running this project, you will get:

A Trained and Validated Intrusion Detection Model: The .joblib files represent a high-performance classifier that has been rigorously tested against overfitting.

A Functional Web-Based Prototype: A real-time network traffic analyzer with a user-friendly interface. The prototype provides:

Dual-Mode Analysis: Choose between fast binary detection or detailed multi-class categorization.

Real-Time Verdicts: Instant classification of network flow data.

Confidence Scores: Insight into how certain the model is about its prediction.

Explainability (XAI): For attack verdicts, the tool lists the top features that influenced the decision, providing valuable context for security analysts.

A Comprehensive Research Framework: A complete, end-to-end example of a machine learning project in cybersecurity, from data engineering to deployment and testing.