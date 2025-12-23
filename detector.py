# detector.py

import datetime
import numpy as np
from collections import deque
from sklearn.ensemble import IsolationForest


class AdvancedAnomalyDetector:
    """
    Machine Learning based anomaly detector using IsolationForest.
    - Recent file events ko feature vectors ke form me store karta hai
    - Periodically model ko train karta hai
    - Anomalous event pe alert_callback() ko call karta hai (agar diya ho)
    """

    def __init__(
        self,
        threshold=10,         # minimum events before ML useful
        time_window=60,       # seconds window for recent events
        train_interval=30,    # seconds between retraining
        max_samples=1000,     # max samples memory me
        alert_callback=None,  # function(message, severity, context_dict)
    ):
        self.threshold = threshold
        self.time_window = time_window
        self.event_queue = deque()
        self.samples = deque(maxlen=max_samples)
        self.train_interval = train_interval
        self.last_trained = datetime.datetime.now()
        self.model = None
        self.alert_callback = alert_callback

    def _train_model(self):
        # Agar data hi kam hai to train nahi karna
        if len(self.samples) < self.threshold * 2:
            return

        feature_matrix = np.array(self.samples)

        # contamination = anomaly ka expected fraction
        contamination = float(self.threshold) / len(self.samples)
        if contamination <= 0:
            contamination = 0.01

        self.model = IsolationForest(
            contamination=contamination,
            n_estimators=100,
            random_state=42,
        )
        self.model.fit(feature_matrix)

    def add_event(self, feature_vector, meta=None):
        """
        feature_vector: [event_type, file_size] jaisa numeric list
        meta: optional dict e.g. {"path": "...", "event": "created"}
        """
        current_time = datetime.datetime.now()
        self.event_queue.append((current_time, feature_vector))
        self.samples.append(feature_vector)

        # time_window se purane events hatao
        while self.event_queue and (current_time - self.event_queue[0][0]).seconds > self.time_window:
            self.event_queue.popleft()

        # periodic retrain
        if (current_time - self.last_trained).seconds > self.train_interval:
            self._train_model()
            self.last_trained = current_time

        # agar model trained hai to anomaly check karo
        if self.model is not None:
            prediction = self.model.predict([feature_vector])   # 1 = normal, -1 = anomaly
            if prediction[0] == -1:
                message = "Anomaly detected: unusual event pattern!"
                severity = "HIGH"
                context = meta or {}

                print(f"[ML-ALERT][{severity}] {message} | Context: {context}")

                # agar idps.py ne alert_callback diya hai to use call karo
                if self.alert_callback:
                    try:
                        self.alert_callback(message, severity, context)
                    except Exception as e:
                        print(f"[ML-ALERT] alert_callback error: {e}")

                # burst handle karne ke liye queue clear
                self.event_queue.clear()

