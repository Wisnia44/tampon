import pandas as pd
import numpy as np
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.model_selection import train_test_split
from sklearn.naive_bayes import MultinomialNB
from sklearn.metrics import classification_report
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import AllowAny
from rest_framework.exceptions import ValidationError
from antispam.serializers import FilterSerializer


def spamFilter(email_body, email_from, sensitivity, blacklist):

    if email_from in blacklist:
        return 1
    df = pd.read_csv("src/spam.csv", encoding="latin-1")
    df.drop(["Unnamed: 2", "Unnamed: 3", "Unnamed: 4"], axis=1, inplace=True)
    df["label"] = df["v1"].map({"ham": 0, "spam": 1})
    X = df["v2"]
    y = df["label"]
    cv = CountVectorizer()
    X = cv.fit_transform(X)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.33, random_state=42
    )
    if sensitivity == "low":
        clf = MultinomialNB(class_prior=[0.1, 0.1])
    elif sensitivity == "medium":
        clf = MultinomialNB(class_prior=[0.1, 0.5])
    else:
        clf = MultinomialNB(class_prior=[0.1, 0.8])
    clf.fit(X_train, y_train)
    clf.score(X_test, y_test)

    data = [email_body]
    vect = cv.transform(data).toarray()
    if clf.predict(vect) == 1:
        return 1
    else:
        return 0


class SpamView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = FilterSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.data

        result = spamFilter(
            data["email_body"],
            data["email_from"],
            data["sensitivity"],
            data["blacklist"],
        )
        return Response(result)
