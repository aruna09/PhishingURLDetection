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
accuracyKNN = accuracy_score(labelsTest, predicted)


"""# SVM: 1.0
from sklearn import svm
model = svm.SVC()
model.fit(featuresTrain, labelsTrain)
predicted = model.predict(featuresTest)
accuracySVM = accuracy_score(labelsTest, predicted)
accuracySVM

# Naive Bayes: 1.0
from sklearn.naive_bayes import GaussianNB
model = GaussianNB()
model.fit(featuresTrain, labelsTrain)
predicted = model.predict(featuresTest)
accuracyNB = accuracy_score(labelsTest, predicted)
accuracyNB

# Decision Tree: 1.0
from sklearn import tree
model = tree.DecisionTreeClassifier()
model.fit(featuresTrain, labelsTrain)
predicted = model.predict(featuresTest)
accuracyDT = accuracy_score(labelsTest, predicted)
print accuracyDT"""