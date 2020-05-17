from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status
from django.http import JsonResponse
from django.core import serializers
from django.conf import settings
import json
import pandas as pd
import numpy as np
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.model_selection import train_test_split
from sklearn.naive_bayes import MultinomialNB
from sklearn.metrics import classification_report



def spamFilter(email_body, email_from, sensivity, blacklist):
	
		if email_from in blacklist:
			return 1
        df = pd.read_csv('spam.csv', encoding="latin-1")
        df.drop(['Unnamed: 2', 'Unnamed: 3', 'Unnamed: 4'], axis=1, inplace=True)
        df['label'] = df['v1'].map({'ham': 0, 'spam': 1})
        X = df['v2']
        y = df['label']
        cv = CountVectorizer()
        X = cv.fit_transform(X) 
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.33, random_state=42)
        if sensivity == 'low':
			clf = MultinomialNB(class_prior = [.1, .1])
		elif: sensivity == 'medium':
			clf = MultinomialNB(class_prior = [.1, .5])
		else:
			clf = MultinomialNB(class_prior = [.1, .8])
		clf.fit(X_train,y_train)
		clf.score(X_test,y_test)
		
        data = [email_body]
        vect = cv.transform(data).toarray()
        if clf.predict(vect) == 1:
			return 1
		else:
			return 0
