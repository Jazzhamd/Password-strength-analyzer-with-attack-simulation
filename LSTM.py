import pandas as pd
import numpy as np
import tensorflow as tf
import pickle
from tensorflow.keras.preprocessing.text import Tokenizer
from tensorflow.keras.preprocessing.sequence import pad_sequences
from tensorflow.keras.utils import to_categorical
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Embedding, LSTM, Dense, Dropout


data = pd.read_csv('data.csv', on_bad_lines='skip')
data.dropna(inplace=True)

passwords = data['password'].astype(str)
strengths = data['strength']


from sklearn.model_selection import train_test_split
X_train, X_test, y_train, y_test = train_test_split(passwords, strengths, test_size=0.2, random_state=42)

tokenizer_cls = Tokenizer(char_level=True)
tokenizer_cls.fit_on_texts(X_train)
with open('tokenizer_cls.pkl','wb') as f:
    pickle.dump(tokenizer_cls,f)
X_train_seq = tokenizer_cls.texts_to_sequences(X_train)
X_test_seq = tokenizer_cls.texts_to_sequences(X_test)

maxLen = 20
X_train_pad = pad_sequences(X_train_seq, maxlen=maxLen)
X_test_pad = pad_sequences(X_test_seq, maxlen=maxLen)

y_train_cat = to_categorical(y_train, num_classes=3)
y_test_cat = to_categorical(y_test, num_classes=3)

model_cls = Sequential([
    Embedding(input_dim=len(tokenizer_cls.word_index) + 1, output_dim=64, input_length=maxLen),
    LSTM(128),
    Dropout(0.5),
    Dense(64, activation='relu'),
    Dense(3, activation='softmax')
])

model_cls.compile(loss='categorical_crossentropy', optimizer='adam', metrics=['accuracy'])
model_cls.fit(X_train_pad, y_train_cat, epochs=5, batch_size=256, validation_split=0.1, verbose=1)


loss, acc = model_cls.evaluate(X_test_pad, y_test_cat)
print(f"\nPassword Strength Classifier Accuracy: {acc*100:.2f}%")
model_cls.save('model_cls.keras')
