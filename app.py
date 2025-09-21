# Cybersecurity Network Traffic Analyzer

import joblib
import pandas as pd
import numpy as np
import re
from flask import Flask, request, render_template_string, url_for

# Initializing the Flask web application
app = Flask(__name__)

# Loading all saved models and supporting files 
try:
    # BINARY model files
    binary_model = joblib.load('binary_model.joblib')
    binary_scaler = joblib.load('binary_scaler.joblib')
    binary_features = joblib.load('binary_feature_columns.joblib')

    # MULTI-CLASS model files
    multi_class_model = joblib.load('multi_class_model.joblib')
    multi_class_scaler = joblib.load('multi_class_scaler.joblib')
    multi_class_encoder = joblib.load('multi_class_encoder.joblib')
    multi_class_features = joblib.load('multi_class_features.joblib')
    
    # Feature importance calculation for the reasoning logic for BOTH models
    binary_feature_importances = pd.Series(binary_model.feature_importances_, index=binary_features).sort_values(ascending=False)
    # --- UPDATE: Added feature importance for the multi-class model ---
    multi_class_feature_importances = pd.Series(multi_class_model.feature_importances_, index=multi_class_features).sort_values(ascending=False)
    
    print("All models and supporting files loaded successfully.")
except FileNotFoundError as e:
    print(f"FATAL ERROR: A required model file was not found: {e.name}.")
    print("Please ensure all .joblib files from the notebook are in the same directory as this app.")
    exit()
except Exception as e:
    print(f"An error occurred while loading files: {e}")
    exit()

# Pre-loaded Test Data Samples for Easy Validation
TEST_SAMPLES = {
    "Benign": "443.0,6.0,121840.0,7.0,8.0,346.0,3935.0,189.0,0.0,49.4285714285714,76.87187856612921,1460.0,0.0,491.875,647.827233913487,35136.0,123.0,8702.857142857141,10040.1603025599,32142.0,1.0,105022.0,17503.6666666667,13081.2057497261,32183.0,285.0,104753.0,14964.7142857143,18480.6389654532,49746.0,1.0,0.0,0.0,0.0,0.0,152.0,172.0,57.4523965856861,65.6598818122127,0.0,1460.0,267.5625,502.023368479994,252027.4625,0.0,0.0,0.0,1.0,0.0,0.0,0.0,0.0,1.0,285.4,49.4285714285714,491.875,0.0,0.0,0.0,0.0,0.0,0.0,7.0,346.0,8.0,3935.0,8192.0,946.0,3.0,20.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0",
    "Botnet": "8080.0,6.0,11537.0,3.0,4.0,326.0,129.0,326.0,0.0,108.6666667,188.2161878,112.0,0.0,32.25,53.7672453,39438.0,606.0,1922.833333,4322.446595,10739.0,0.0,498.0,249.0,280.01428530000004,447.0,51.0,11110.0,3703.333333,6095.889134,10739.0,0.0,0.0,0.0,0.0,0.0,72.0,92.0,260.0329375,346.7105833,0.0,326.0,56.875,115.4066568,13318.69643,0.0,0.0,1.0,1.0,0.0,0.0,0.0,1.0,1.0,65.0,108.6666667,32.25,0.0,0.0,0.0,0.0,0.0,0.0,3.0,326.0,4.0,129.0,8192.0,219.0,1.0,20.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0",
    "DoS-Hulk": "80.0,6.0,30432.0,2.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,65.0,30432.0,0.0,30432.0,30432.0,30432.0,30432.0,0.0,30432.0,30432.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,64.0,0.0,65.72029443,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,1.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,2.0,0.0,0.0,0.0,225.0,-1.0,0.0,32.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0",
    "Infiltration": "80.0,6.0,5819885.0,3.0,1.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,1939961.667,3332519.7410000004,5787980.0,15.0,5819885.0,2909942.5,4070159.666,5787980.0,31905.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,72.0,32.0,0.515474103,0.171824701,0.0,0.0,0.0,0.0,0.0,0.0,0.0,1.0,1.0,0.0,0.0,0.0,1.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,3.0,0.0,1.0,0.0,8192.0,29200.0,0.0,20.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0"
}


# Defining HTML Template 
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Advanced Network Threat Analyzer</title>
    {% if result and 'Error:' not in result.verdict %}
    <meta http-equiv="refresh" content="20;url=/">
    {% endif %}
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Roboto+Mono:wght@400;700&display=swap');
        body {
            font-family: 'Roboto Mono', monospace; color: #c9d1d9; text-align: center;
            padding: 20px; margin: 0; min-height: 100vh;
            background-image: url('{{ background_image }}'); background-size: cover;
            background-position: center; background-attachment: fixed; transition: background-image 0.5s ease-in-out;
            display: flex; justify-content: center; align-items: center; box-sizing: border-box;
        }
        .container {
            width: 100%; max-width: 900px; background: rgba(22, 27, 34, 0.9);
            backdrop-filter: blur(10px); padding: 40px; border-radius: 10px;
            border: 1px solid #30363d; box-shadow: 0 0 25px rgba(0, 170, 255, 0.3);
        }
        h1 { color: #58a6ff; text-shadow: 0 0 10px #58a6ff; margin-bottom: 10px; }
        p { color: #8b949e; font-size: 1.1em; }
        .input-area { width: 95%; }
        textarea {
            width: 100%; height: 120px; padding: 15px; background: #0d1117; color: #c9d1d9;
            border: 1px solid #30363d; border-radius: 5px; font-family: 'Roboto Mono', monospace;
            font-size: 1em; resize: none; box-sizing: border-box;
        }
        .controls { display: flex; justify-content: space-between; align-items: center; margin-top: 20px; }
        select, button {
            padding: 14px 28px; border: none; border-radius: 5px; font-size: 1.1em; font-weight: bold;
            font-family: 'Roboto Mono', monospace;
        }
        select { background: #0d1117; color: #c9d1d9; border: 1px solid #30363d; }
        button { background-color: #238636; color: white; cursor: pointer; transition: all 0.3s ease; }
        button:hover { background-color: #2ea043; box-shadow: 0 0 25px rgba(46, 160, 67, 0.7); }
        .result {
            margin-top: 30px; padding: 20px; border-radius: 5px; font-size: 1.6em;
            font-weight: bold; text-transform: uppercase;
        }
        .benign { background-color: rgba(35, 134, 54, 0.2); color: #3fb950; border: 1px solid #3fb950; }
        .attack { background-color: rgba(248, 81, 73, 0.2); color: #f85149; border: 1px solid #f85149; }
        .hint { font-size: 0.8em; color: #8b949e; margin-top: 10px; text-align: left; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Advanced Network Threat Analyzer</h1>
        <p>Input a network flow vector for real-time threat classification.</p>
        <form action="/" method="post">
            <div class="input-area">
                <textarea name="flow_data" placeholder="Paste a comma-separated numerical vector representing a network flow...">{{ user_input }}</textarea>
                <div class="hint">
                    <b>Hint:</b> For testing, copy-paste a sample vector from the dictionary.
                </div>
            </div>
            <div class="controls">
                <select name="analysis_mode">
                    <option value="binary" {% if mode == 'binary' %}selected{% endif %}>Binary Scan (Benign/Attack)</option>
                    <option value="multi" {% if mode == 'multi' %}selected{% endif %}>Detailed Threat Analysis</option>
                </select>
                <button type="submit">Analyze Vector</button>
            </div>
        </form>
        {% if result %}
            <div class="result {{ result.class }}">
                {% if result.verdict.startswith('Error:') %}
                    {{ result.verdict }}
                {% else %}
                    CLASSIFICATION: {{ result.verdict }} 
                    <span style="font-size:0.7em; opacity:0.8;">(CONFIDENCE: {{ result.confidence }})</span>
                {% endif %}
            </div>
            {% if result.reason %}
            <p class="hint" style="text-align:center; margin-top:15px;"><b>Reasoning:</b> {{ result.reason }}</p>
            {% endif %}
            {% if result and 'Error:' not in result.verdict %}
            <p class="hint" style="text-align:center; margin-top:15px;">This page will automatically refresh in 20 seconds.</p>
            {% endif %}
        {% endif %}
    </div>
</body>
</html>
"""

# Main Application Logic 
@app.route('/', methods=['GET', 'POST'])
def index():
    result = None
    user_input = ""
    analysis_mode = "binary"  # Default mode
    # Set the default background image
    background_image = url_for('static', filename='first.jpeg')

    if request.method == 'POST':
        user_input = request.form['flow_data']
        analysis_mode = request.form['analysis_mode']
        
        # Robust input sanitization and validation
        if not user_input.strip():
            result = {'verdict': 'Error: Please enter a network flow vector to analyze.', 'class': 'attack'}
            background_image = url_for('static', filename='attack.jpeg')
            return render_template_string(HTML_TEMPLATE, result=result, user_input=user_input, background_image=background_image, mode=analysis_mode)
        
        if len(user_input) > 5000: # Prevent excessively long inputs
            result = {'verdict': 'Error: Input data is too long.', 'class': 'attack'}
            background_image = url_for('static', filename='attack.jpeg')
            return render_template_string(HTML_TEMPLATE, result=result, user_input=user_input, background_image=background_image, mode=analysis_mode)

        if not re.match(r'^[0-9.,\s-]*$', user_input):
            result = {'verdict': 'Error: Input contains invalid characters.', 'class': 'attack'}
            background_image = url_for('static', filename='attack.jpeg')
            return render_template_string(HTML_TEMPLATE, result=result, user_input=user_input, background_image=background_image, mode=analysis_mode)

        try:
            # Prepare the input data
            flow_values = [float(val) for val in user_input.strip().split(',')]
            verdict = ""
            result_class = "attack" # Default to attack for errors
            confidence = "N/A"
            reason = None

            if analysis_mode == 'binary':
                # Using Binary Model 
                if len(flow_values) != len(binary_features):
                    raise ValueError(f"Incorrect number of features for Binary Scan. Expected {len(binary_features)}, got {len(flow_values)}.")
                
                input_df = pd.DataFrame([flow_values], columns=binary_features)
                input_scaled = binary_scaler.transform(input_df)
                
                # Get prediction probabilities for confidence score
                probabilities = binary_model.predict_proba(input_scaled)[0]
                prediction = np.argmax(probabilities)
                confidence = f"{probabilities[prediction]*100:.2f}%"
                verdict = 'Attack' if prediction == 1 else 'Benign'

                # Added the reasoning logic for attack verdicts
                if verdict == 'Attack':
                    top_features = binary_feature_importances.head(5).index.tolist()
                    reason = f"Flagged due to high contribution from features like: {', '.join(top_features)}."

            elif analysis_mode == 'multi':
                # Using Multi-Class Model 
                if len(flow_values) != len(multi_class_features):
                    raise ValueError(f"Incorrect number of features for Detailed Analysis. Expected {len(multi_class_features)}, got {len(flow_values)}.")

                input_df = pd.DataFrame([flow_values], columns=multi_class_features)
                input_scaled = multi_class_scaler.transform(input_df)
                
                # Get prediction probabilities for confidence score
                probabilities = multi_class_model.predict_proba(input_scaled)[0]
                prediction_index = np.argmax(probabilities)
                confidence = f"{probabilities[prediction_index]*100:.2f}%"
                verdict = multi_class_encoder.inverse_transform([prediction_index])[0]
                
                # Added the reasoning logic for multi-class attack 
                if 'benign' not in verdict.lower():
                    top_features = multi_class_feature_importances.head(5).index.tolist()
                    reason = f"Flagged as {verdict} due to high contribution from features like: {', '.join(top_features)}."
            
            # Determine background and CSS class based on verdict
            if 'benign' in verdict.lower():
                background_image = url_for('static', filename='safe.jpeg')
                result_class = 'benign'
            else:
                background_image = url_for('static', filename='attack.jpeg')
                result_class = 'attack'
            
            result = {'verdict': verdict, 'class': result_class, 'confidence': confidence, 'reason': reason}

        except Exception as e:
            result = {'verdict': f'Error: {e}', 'class': 'attack'}
            background_image = url_for('static', filename='attack.jpeg')

    return render_template_string(HTML_TEMPLATE, result=result, user_input=user_input, background_image=background_image, mode=analysis_mode)

# Run the Web Server 
if __name__ == '__main__':
    # host='0.0.0.0' makes the server accessible from any device on the network.
    # debug=False should be used for any production deployment
    app.run(host='0.0.0.0', debug=True)