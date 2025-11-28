# Testing ML Features Locally - Quick Start Guide

## Prerequisites

First, install the ML dependencies:
```bash
pip install scikit-learn numpy pandas joblib
```

## Local Testing Workflow

### Step 1: Start the Development Server

```bash
cd waf_project
python manage.py runserver
```

The server will start at `http://localhost:8000`

### Step 2: Access Django Admin

1. Navigate to `http://localhost:8000/admin/`
2. Login with your superuser credentials
3. You should see new ML sections:
   - **WAF Machine Learning** section with:
     - Adaptive Rules
     - Anomaly Scores
     - False Positive Feedback
     - ML Models
     - Rule Learning Histories
     - Traffic Patterns

### Step 3: Verify ML is Enabled

Check the console output when the server starts. You should see:
```
DEBUG: ML_AVAILABLE = True
```

If you see this, ML features are active!

---

## Testing Each Feature

### 🎯 Feature 1: Feature Extraction (Automatic)

**What happens**: Every request automatically extracts 30+ features

**How to verify**:
1. Make any request to your WAF-protected domain
2. Check the console - you'll see debug output like:
   ```
   DEBUG: WAF processing request: /api/users
   DEBUG: Extracting features...
   ```

**Expected behavior**: No errors, request processes normally

---

### 🤖 Feature 2: Anomaly Detection

**What happens**: ML model scores each request for anomalies

**Setup required**: You need a trained model first!

#### Train Your First Model

1. **Generate legitimate traffic** (at least 100 requests):
   ```bash
   # Simple script to generate traffic
   for i in {1..150}; do
       curl http://localhost:8000/api/users?page=$i
   done
   ```

2. **Train the model**:
   ```bash
   python manage.py train_ml_models --tenant yourdomain.com
   ```

3. **Check output**:
   ```
   Training model for tenant: Your Tenant
   Collected 150 training samples
   ✓ Model v1 trained successfully!
     - Samples: 150
     - Duration: 2.34s
     - Anomaly rate: 8.67%
   ```

4. **Verify in admin**:
   - Go to **ML Models** in admin
   - You should see a new model with `is_active=True`

#### Test Anomaly Detection

1. **Send a normal request**:
   ```bash
   curl http://localhost:8000/api/users
   ```
   
   **Expected**: Request allowed, low anomaly score logged

2. **Send a suspicious request**:
   ```bash
   curl "http://localhost:8000/api/users?id=1' UNION SELECT password FROM users--"
   ```
   
   **Expected**: 
   - Request blocked with 403 Forbidden
   - Console shows: `ML Anomaly detected: 192.168.1.1 - Score: 0.856`
   - Anomaly score logged in database

3. **Check anomaly scores in admin**:
   - Go to **Anomaly Scores**
   - You should see entries with scores (0.0 to 1.0)
   - High scores (>0.7) should be marked as anomalies

---

### 📊 Feature 3: Adaptive Rule Suggestion

**What happens**: System analyzes blocked attacks and suggests new rules

#### Generate Attack Data

1. **Send multiple similar attacks** (at least 5):
   ```bash
   for i in {1..10}; do
       curl "http://localhost:8000/api/users?id=$i UNION SELECT password FROM users"
   done
   ```

2. **Run rule suggestion**:
   ```bash
   python manage.py suggest_rules --tenant yourdomain.com
   ```

3. **Check output**:
   ```
   Analyzing patterns for tenant: Your Tenant
   Analyzing 10 blocked events...
   Found 2 potential rules:
     ○ Auto-detected sql_injection pattern
        Confidence: 85.00%
        Attacks: 10
        Status: PENDING
   ✓ Created 1 adaptive rule(s)
   ```

4. **Review in admin**:
   - Go to **Adaptive Rules**
   - You should see pending rules with confidence scores
   - Click on a rule to see:
     - Suggested pattern (regex)
     - Attack count
     - Supporting event IDs

#### Approve an Adaptive Rule

1. **In admin**, select a pending rule
2. **Click "Approve selected rules"** action
3. **Verify**:
   - Rule status changes to "approved"
   - A new **Firewall Rule** is created
   - Future matching requests are blocked

---

### 🔄 Feature 4: False Positive Feedback

**What happens**: Users can report false positives to improve the system

#### Submit False Positive via API

```bash
# Get a security event ID from admin first
curl -X POST http://localhost:8000/api/ml/feedback/ \
  -H "Content-Type: application/json" \
  -H "Authorization: Token YOUR_TOKEN" \
  -d '{
    "security_event": "event-uuid-here",
    "tenant": "tenant-uuid-here",
    "is_false_positive": true,
    "user_comment": "This was a legitimate request from our mobile app",
    "reported_by": "admin@example.com"
  }'
```

**Expected response**:
```json
{
  "id": "feedback-uuid",
  "is_false_positive": true,
  "resolved": false,
  "created_at": "2025-11-28T11:20:00Z"
}
```

**Verify in admin**:
- Go to **False Positive Feedback**
- You should see the new feedback entry
- Mark it as resolved with an action

---

## Visual Indicators That ML is Working

### ✅ Console Output

When ML is working, you'll see:
```
DEBUG: WAF processing request: /api/users
DEBUG: ML enabled: True
DEBUG: Extracting features...
DEBUG: Checking ML anomaly...
DEBUG: Anomaly score: 0.234 (threshold: 0.7)
DEBUG: Request allowed
```

### ✅ Admin Dashboard

You should see data in these sections:
- **Anomaly Scores**: Growing list of scored requests
- **ML Models**: At least one active model
- **Adaptive Rules**: Suggested rules (if attacks detected)
- **Traffic Patterns**: Aggregated statistics

### ✅ API Responses

Test the insights API:
```bash
curl http://localhost:8000/api/ml/insights/ \
  -H "Authorization: Token YOUR_TOKEN"
```

**Expected response**:
```json
{
  "adaptive_rules": {
    "total": 2,
    "pending_review": 1
  },
  "ml_models": {
    "active": 1
  },
  "anomalies": {
    "last_7_days": 23
  },
  "feedback": {
    "total": 5,
    "resolved": 3,
    "pending": 2
  }
}
```

---

## Troubleshooting

### Issue: "No module named 'numpy'"

**Solution**:
```bash
pip install scikit-learn numpy pandas joblib
```

### Issue: "Not enough training samples"

**Solution**: Generate more legitimate traffic (need at least 100 requests)
```bash
for i in {1..150}; do curl http://localhost:8000/api/users?page=$i; done
```

### Issue: "No trained model yet"

**Solution**: Train a model first
```bash
python manage.py train_ml_models --tenant yourdomain.com
```

### Issue: ML features not working

**Check**:
1. `WAF_ML_ENABLED = True` in settings.py
2. ML dependencies installed
3. Console shows `ML_AVAILABLE = True`
4. Tenant has active WAF configuration

---

## Quick Verification Checklist

Run through this checklist to verify everything works:

- [ ] **Server starts without errors**
  ```bash
  python manage.py runserver
  ```

- [ ] **ML sections visible in admin**
  - Navigate to `/admin/`
  - See "WAF Machine Learning" section

- [ ] **Feature extraction works**
  - Make a request
  - No errors in console

- [ ] **Model training works**
  ```bash
  python manage.py train_ml_models --tenant yourdomain.com
  ```
  - See success message
  - Model appears in admin

- [ ] **Anomaly detection works**
  - Send normal request → allowed
  - Send attack → blocked (if model trained)
  - Anomaly scores logged

- [ ] **Rule suggestion works**
  ```bash
  python manage.py suggest_rules --tenant yourdomain.com
  ```
  - See suggested rules
  - Rules appear in admin

- [ ] **API endpoints work**
  ```bash
  curl http://localhost:8000/api/ml/insights/ -H "Authorization: Token YOUR_TOKEN"
  ```
  - Get JSON response with stats

---

## Performance Monitoring

### Check Request Latency

**Without ML**:
```bash
time curl http://localhost:8000/api/users
# ~50ms
```

**With ML** (feature extraction + anomaly detection):
```bash
time curl http://localhost:8000/api/users
# ~55-60ms (5-10ms overhead)
```

**Expected overhead**: 5-10ms per request

### Monitor Database

Check anomaly score table size:
```bash
python manage.py dbshell
SELECT COUNT(*) FROM waf_ml_anomalyscore;
```

If growing too large, consider archiving old scores.

---

## Real-World Testing Scenario

### Complete End-to-End Test

1. **Setup** (5 minutes):
   ```bash
   # Install dependencies
   pip install scikit-learn numpy pandas joblib
   
   # Start server
   python manage.py runserver
   ```

2. **Generate baseline traffic** (2 minutes):
   ```bash
   # 150 legitimate requests
   for i in {1..150}; do
       curl http://localhost:8000/api/users?page=$i
       sleep 0.1
   done
   ```

3. **Train model** (1 minute):
   ```bash
   python manage.py train_ml_models --tenant yourdomain.com
   ```

4. **Test anomaly detection** (1 minute):
   ```bash
   # Normal request - should be allowed
   curl http://localhost:8000/api/users
   
   # Attack - should be blocked
   curl "http://localhost:8000/api/users?id=1' OR '1'='1"
   ```

5. **Generate attack patterns** (2 minutes):
   ```bash
   for i in {1..10}; do
       curl "http://localhost:8000/api/users?id=$i UNION SELECT password"
   done
   ```

6. **Suggest rules** (1 minute):
   ```bash
   python manage.py suggest_rules --tenant yourdomain.com
   ```

7. **Approve rule in admin** (1 minute):
   - Go to Adaptive Rules
   - Select pending rule
   - Click "Approve selected rules"

8. **Verify rule works** (1 minute):
   ```bash
   # Should now be blocked by adaptive rule
   curl "http://localhost:8000/api/test?x=UNION SELECT"
   ```

**Total time**: ~15 minutes

**Success criteria**:
- ✅ Model trained successfully
- ✅ Anomalies detected and logged
- ✅ Adaptive rule suggested
- ✅ Approved rule blocks matching requests

---

## Next Steps

Once verified locally:
1. Deploy to staging environment
2. Monitor for 1-2 weeks
3. Review false positive rate
4. Adjust thresholds if needed
5. Deploy to production

**Recommended settings for production**:
```python
WAF_ML_ANOMALY_THRESHOLD = 0.75  # Slightly higher to reduce FPs
WAF_ML_AUTO_APPROVE_THRESHOLD = 0.98  # Very high for auto-approval
WAF_ML_MIN_SAMPLES_FOR_TRAINING = 500  # More samples for better accuracy
```
