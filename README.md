# Password-Strength-Analyzer-And-Attack-Simulator

<div>
 
[![](https://img.shields.io/badge/Python-02569B?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![](https://img.shields.io/badge/Flask-000000?style=for-the-badge&logo=flask&logoColor=white)](https://flask.palletsprojects.com/en/2.0.x/)
[![](https://img.shields.io/badge/Visual_Studio-CC0000?style=for-the-badge&logo=visual%20studio&logoColor=white)](https://code.visualstudio.com/  "Visual Studio Code")
  
Features:
  1. Password strength classifier based on LSTM output. Trained using dataset from Kaggle (link below).
  
  2. Estimated crack time visualizations. Crack times are computed using Python's zxcvbn module. Local brute force estimations are also computed.
  
  3. Generate password feature. Implemented using Python's secrets module, which is a cryptographically secure random number generator.

  4. Attack simulations using dictionary and mask attack methods. These attacks have been heavily limited and throttled to avoid infinite computations and application crashing. 

  Dataset link : https://www.kaggle.com/datasets/bhavikbb/password-strength-classifier-dataset

  Instructions to run:
  1. Install required modules using pip install -r requirements.txt

  2. Run app.py. App wil start running in localhost.


</div>
