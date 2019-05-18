import pandas as pd
import numpy as np
from sklearn.metrics import accuracy_score
from sklearn.model_selection import train_test_split
from preprocess import *

data = pd.read_csv("train.csv")
# dropping certain feature columns which weren't implemented.
# "URL_of_Anchor"
# "Add "Favicon",  in drop list"
data = data.drop(["Favicon", "URL_of_Anchor", "Iframe", "Links_in_tags", "SFH", "popUpWidnow", "RightClick", "port", "on_mouseover", "Page_Rank", "Google_Index", "Links_pointing_to_page", "Statistical_report"], axis=1)
features, labels = data.iloc[:, 1:18], data.iloc[:, 19]
featuresTrain, featuresTest, labelsTrain, labelsTest = train_test_split(features, labels, test_size=0.4, random_state=0)
print(data.columns)
testFeature = np.array(testFeature)
testFeature = testFeature.reshape(1, -1)
print(testFeature.shape)
# Decision Tree: 0.9138398914518318
from sklearn import tree
model = tree.DecisionTreeClassifier()
model.fit(featuresTrain, labelsTrain)
predicted = model.predict(testFeature)
accuracyDT = accuracy_score(testLabel, predicted)
print(accuracyDT)

"""
# k-NN: 0.878561736770692
from sklearn.neighbors import KNeighborsClassifier
model=KNeighborsClassifier(n_neighbors=2)
model.fit(featuresTrain, labelsTrain)
predicted=model.predict(featuresTest)
accuracyKNN = accuracy_score(labelsTest, predicted)
print(accuracyKNN)


# SVM: 1.0
from sklearn import svm
model = svm.SVC()
model.fit(featuresTrain, labelsTrain)
predicted = model.predict(featuresTest)
accuracySVM = accuracy_score(labelsTest, predicted)
print(accuracySVM)

# Naive Bayes: 1.0
from sklearn.naive_bayes import GaussianNB
model = GaussianNB()
model.fit(featuresTrain, labelsTrain)
predicted = model.predict(featuresTest)
accuracyNB = accuracy_score(labelsTest, predicted)
print(accuracyNB)

"""