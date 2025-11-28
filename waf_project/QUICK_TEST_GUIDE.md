# 🎯 How to Test ML Features Locally - Quick Reference

## When You Run Locally, Here's What Happens:

### 1. **Automatic Feature Extraction** ✅
- **Every request** automatically extracts 30+ features
- **No action needed** - happens in background
- **Check console** for debug messages:
  ```
  DEBUG: Extracting features...
  DEBUG: Anomaly score: 0.234
  ```

### 2. **Anomaly Detection** (if model trained) 🤖
- **Normal requests** → Allowed (score < 0.7)
- **Suspicious requests** → Blocked (score ≥ 0.7)
- **Logged** in database for analysis

### 3. **Adaptive Rules** (if approved) 📊
- **ML-generated rules** automatically block matching patterns
- **Visible in admin** under "Adaptive Rules"

---

## Quick Test (5 Minutes)

### Option 1: Use Demo Script (Easiest!)

```bash
# Install demo dependencies
pip install requests colorama

# Run demo
python demo_ml_features.py --tenant yourdomain.com
```

**What it does**:
1. ✅ Generates 150 legitimate requests
2. ✅ Tests anomaly detection
3. ✅ Generates attack patterns
4. ✅ Shows you what to do next

### Option 2: Manual Testing

```bash
# 1. Start server
python manage.py runserver

# 2. Generate traffic (in another terminal)
for i in {1..150}; do curl http://localhost:8000/api/users?page=$i; done

# 3. Train model
python manage.py train_ml_models --tenant yourdomain.com

# 4. Test attack
curl "http://localhost:8000/api/users?id=1' OR '1'='1"
# Should return 403 Forbidden!
```

---

## How to Know It's Working

### ✅ Visual Indicators

**1. Console Output:**
```
DEBUG: WAF processing request: /api/users
DEBUG: ML enabled: True
DEBUG: Anomaly score: 0.234 (threshold: 0.7)
DEBUG: Request allowed
```

**2. Django Admin:**
- Go to `/admin/`
- See "WAF Machine Learning" section
- Check **Anomaly Scores** - should have entries
- Check **ML Models** - should have 1 active model

**3. API Response:**
```bash
curl http://localhost:8000/api/ml/insights/
```
Returns:
```json
{
  "adaptive_rules": {"total": 2, "pending_review": 1},
  "ml_models": {"active": 1},
  "anomalies": {"last_7_days": 23}
}
```

---

## Expected Behavior

| Action | Without ML | With ML (Trained) |
|--------|-----------|------------------|
| Normal request | ✅ Allowed | ✅ Allowed (score ~0.2-0.4) |
| SQL injection | ⚠️ Allowed | ❌ Blocked (score ~0.8-0.95) |
| XSS attack | ⚠️ Allowed | ❌ Blocked (score ~0.7-0.9) |
| Unusual pattern | ⚠️ Allowed | ⚠️ Logged (score ~0.5-0.7) |

---

## Troubleshooting

### "No module named 'numpy'"
```bash
pip install scikit-learn numpy pandas joblib
```

### "Not enough training samples"
Generate more traffic:
```bash
for i in {1..200}; do curl http://localhost:8000/api/users?page=$i; done
```

### "No trained model yet"
Train a model:
```bash
python manage.py train_ml_models --tenant yourdomain.com
```

### ML not working
Check:
1. ✅ `WAF_ML_ENABLED = True` in settings
2. ✅ ML dependencies installed
3. ✅ Server shows `ML_AVAILABLE = True`
4. ✅ Tenant has WAF config enabled

---

## Performance Impact

- **Feature extraction**: +5-10ms per request
- **Anomaly detection**: +1-2ms per request
- **Total overhead**: ~10ms (negligible)

---

## Files to Check

1. **Console** - Real-time debug output
2. **Admin → Anomaly Scores** - All scored requests
3. **Admin → ML Models** - Trained models
4. **Admin → Adaptive Rules** - Suggested rules
5. **Admin → Security Events** - Blocked attacks

---

## Next Steps After Verification

1. ✅ Verify locally (15 minutes)
2. 📊 Monitor for 1-2 weeks
3. 🔧 Adjust thresholds if needed
4. 🚀 Deploy to production

---

## Need More Details?

See **LOCAL_TESTING_GUIDE.md** for comprehensive instructions!
