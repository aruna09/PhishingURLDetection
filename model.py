import pandas as pd
import numpy as np
from sklearn.metrics import accuracy_score


data = pd.read_csv("train.csv")
data.head()
data.describe()
data.columns

from sklearn.model_selection import train_test_split
features, labels = data.iloc[:, 1:], data.iloc[:, 31]
featuresTrain, featuresTest, labelsTrain, labelsTest=train_test_split(features, labels, test_size=0.4, random_state=0)

# Trying out various classifiers:

# k-NN: 0.9981908638625057
from sklearn.neighbors import KNeighborsClassifier
model=KNeighborsClassifier(n_neighbors=2)
model.fit(featuresTrain, labelsTrain)
predicted=model.predict(featuresTest)
acc_knn = accuracy_score(labelsTest, predicted)
print acc_knn

# SVM 