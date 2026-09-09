import React, { useEffect, useState } from 'react';
import dayjs from 'dayjs';
import logo from './endpoint-shield-solutions-logo.png';

const API_URL = process.env.REACT_APP_API_URL || 'http://127.0.0.1:9000';
// Every /devices call needs this now - app/main.py's device routes are
// JWT-only (tenant-scoped), separate from the API-key scheme agent.ps1
// uses for /agents/heartbeat. sessionStorage (not localStorage) so a
// closed tab requires logging in again, not an indefinite session.
const TOKEN_KEY = 'msp_dashboard_token';
const authHeaders = (token, extra = {}) => ({ ...extra, Authorization: `Bearer ${token}` });

const EMPTY_DEVICE = {
  hostname: '',
  ip: '',
  cpu: '',
  ram: '',
  disk: '',
  os: '',
  location: '',
  notes: ''
};

const mobileStyle = `
  @media (max-width: 700px) {
    .dashboard-topbar { flex-wrap: wrap; }
    .dashboard-logo { font-size: 22px !important; }
    .dashboard-form { flex-direction: column; }
    table { display: block; overflow-x: auto; white-space: nowrap; }
  }
`;

const getStatus = lastSeen => {
  if (!lastSeen)
    return { status: 'Offline', color: 'red', icon: '❌', rowColor: '#ffd6d6' };
  const last = new Date(lastSeen);
  const now = new Date();
  const delta = now - last;
  if (delta < 2 * 60 * 1000) {
    return { status: 'Online', color: 'green', icon: '✅', rowColor: '' };
  } else if (delta < 10 * 60 * 1000) {
    return { status: 'Stale', color: '#b59a00', icon: '⚠️', rowColor: '#fffbe6' };
  } else {
    return { status: 'Offline', color: 'red', icon: '❌', rowColor: '#ffd6d6' };
  }
};

// Pull the message out of a FastAPI error response ({"detail": ...}).
const errorMessage = async (res, fallback) => {
  try {
    const body = await res.json();
    if (typeof body.detail === 'string') return body.detail;
    if (Array.isArray(body.detail) && body.detail.length) {
      return body.detail.map(d => d.msg || JSON.stringify(d)).join('; ');
    }
  } catch (err) {
    /* not JSON — fall through */
  }
  return `${fallback} (HTTP ${res.status})`;
};

function App() {
  const [token, setToken] = useState(() => sessionStorage.getItem(TOKEN_KEY));
  const [loginForm, setLoginForm] = useState({ username: '', password: '' });
  const [loginError, setLoginError] = useState(null);

  const [devices, setDevices] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  // Action failures (add/edit/delete). Kept separate from `error` so the
  // 10-second poll can't wipe a message the user hasn't read yet.
  const [notice, setNotice] = useState(null);
  const [newDevice, setNewDevice] = useState(EMPTY_DEVICE);
  const [editDevice, setEditDevice] = useState(null);
  const [search, setSearch] = useState('');
  const [selected, setSelected] = useState([]);
  // Keys of alerts the user dismissed, e.g. "PC-02|Offline". An alert comes
  // back only when that device's status actually changes.
  const [dismissed, setDismissed] = useState([]);

  const logOut = () => {
    sessionStorage.removeItem(TOKEN_KEY);
    setToken(null);
  };

  const handleLogin = async e => {
    e.preventDefault();
    setLoginError(null);
    try {
      // OAuth2PasswordRequestForm (app/main.py's POST /api/login) expects
      // form-encoded fields, not JSON.
      const body = new URLSearchParams();
      body.set('username', loginForm.username);
      body.set('password', loginForm.password);
      const res = await fetch(`${API_URL}/api/login`, { method: 'POST', body });
      if (!res.ok) {
        setLoginError(await errorMessage(res, 'Login failed'));
        return;
      }
      const data = await res.json();
      sessionStorage.setItem(TOKEN_KEY, data.access_token);
      setToken(data.access_token);
      setLoginForm({ username: '', password: '' });
    } catch (err) {
      setLoginError('Could not reach the login API. Is the backend running?');
    }
  };

  const fetchDevices = async () => {
    setLoading(true);
    try {
      const res = await fetch(`${API_URL}/devices`, { headers: authHeaders(token) });
      if (res.status === 401) {
        logOut(); // expired/invalid token - back to the login screen
        return;
      }
      if (!res.ok) throw new Error(`Request failed: ${res.status}`);
      const data = await res.json();
      setDevices(data);
      setError(null);
    } catch (err) {
      setError('Could not reach the device API. Is the backend running?');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (!token) return;
    fetchDevices();
    const interval = setInterval(fetchDevices, 10000);
    return () => clearInterval(interval);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [token]);

  // Alerts panel — derived from the current device list, minus dismissals.
  const alerts = devices
    .map(d => ({ device: d, status: getStatus(d.last_seen).status }))
    .filter(({ status }) => status === 'Offline' || status === 'Stale')
    .map(({ device, status }) => ({
      key: `${device.hostname}|${status}`,
      message: `Alert: ${device.hostname} is ${status}`
    }))
    .filter(alert => !dismissed.includes(alert.key));

  const handleDismissAlerts = () => {
    setDismissed(devices
      .map(d => `${d.hostname}|${getStatus(d.last_seen).status}`));
  };

  const handleAddDevice = async e => {
    e.preventDefault();
    if (!newDevice.hostname.trim() || !newDevice.ip.trim()) return;
    try {
      const res = await fetch(`${API_URL}/devices`, {
        method: 'POST',
        headers: authHeaders(token, { 'Content-Type': 'application/json' }),
        body: JSON.stringify(newDevice)
      });
      if (!res.ok) {
        // Keep what they typed so the form can be corrected and resubmitted.
        setNotice(await errorMessage(res, 'Could not add the device'));
        return;
      }
      setNewDevice(EMPTY_DEVICE);
      setNotice(null);
      fetchDevices();
    } catch (err) {
      setError('Could not reach the device API. Is the backend running?');
    }
  };

  const handleDeleteDevice = async hostname => {
    try {
      const res = await fetch(`${API_URL}/devices/${encodeURIComponent(hostname)}`, {
        method: 'DELETE',
        headers: authHeaders(token)
      });
      if (!res.ok) {
        setNotice(await errorMessage(res, `Could not delete ${hostname}`));
        return;
      }
      setSelected(sel => sel.filter(h => h !== hostname));
      setNotice(null);
      fetchDevices();
    } catch (err) {
      setError('Could not reach the device API. Is the backend running?');
    }
  };

  const handleBulkDelete = async () => {
    const failed = [];
    try {
      for (const hostname of selected) {
        const res = await fetch(`${API_URL}/devices/${encodeURIComponent(hostname)}`, {
          method: 'DELETE',
          headers: authHeaders(token)
        });
        if (!res.ok) failed.push(hostname);
      }
    } catch (err) {
      setError('Could not reach the device API. Is the backend running?');
      fetchDevices();
      return;
    }
    setSelected(failed);
    setNotice(failed.length ? `Could not delete: ${failed.join(', ')}` : null);
    fetchDevices();
  };

  const handleToggleSelect = (hostname, checked) => {
    setSelected(sel =>
      checked ? [...sel, hostname] : sel.filter(h => h !== hostname)
    );
  };

  const handleSelectAll = checked => {
    setSelected(checked ? filteredDevices.map(device => device.hostname) : []);
  };

  const filteredDevices = devices.filter(
    device =>
      device.hostname.toLowerCase().includes(search.toLowerCase()) ||
      device.ip.toLowerCase().includes(search.toLowerCase()) ||
      (device.os ? device.os.toLowerCase().includes(search.toLowerCase()) : false)
  );

  const inputStyle = { margin: 4, borderRadius: 4, border: '1px solid #b0cbe7', padding: 7 };

  if (!token) {
    return (
      <div
        style={{
          maxWidth: 380,
          margin: '4rem auto',
          padding: 28,
          fontFamily: "'Segoe UI', Helvetica, Arial, sans-serif",
          background: '#fff',
          borderRadius: 12,
          boxShadow: '0 1px 6px #b3c8e6'
        }}
      >
        <img src={logo} alt="Endpoint Shield Solutions" style={{ width: 96, display: 'block', margin: '0 auto 12px' }} />
        <h2 style={{ color: '#2471a3', marginTop: 0, textAlign: 'center' }}>Endpoint Shield Solutions</h2>
        <form onSubmit={handleLogin} style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
          <input
            value={loginForm.username}
            onChange={e => setLoginForm({ ...loginForm, username: e.target.value })}
            placeholder="Username"
            autoFocus
            required
            style={inputStyle}
          />
          <input
            type="password"
            value={loginForm.password}
            onChange={e => setLoginForm({ ...loginForm, password: e.target.value })}
            placeholder="Password"
            required
            style={inputStyle}
          />
          <button
            type="submit"
            style={{
              padding: '8px 18px',
              background: '#2471a3',
              color: '#fff',
              border: 0,
              borderRadius: 6,
              fontWeight: 600,
              cursor: 'pointer'
            }}
          >
            Log in
          </button>
          {loginError && <div style={{ color: '#a12626', fontSize: 14 }}>{loginError}</div>}
        </form>
      </div>
    );
  }

  return (
    <div
      style={{
        maxWidth: 1150,
        margin: '2rem auto',
        padding: 20,
        fontFamily: "'Segoe UI', Helvetica, Arial, sans-serif",
        background: '#fafdff',
        minHeight: '100vh'
      }}
    >
      <style>{mobileStyle}</style>

      {/* Logo and top bar */}
      <div
        className="dashboard-topbar"
        style={{
          background: '#ebf5fb',
          padding: '16px 0',
          display: 'flex',
          alignItems: 'center',
          marginBottom: '32px',
          borderRadius: '8px'
        }}
      >
        <img
          src={logo}
          alt="Endpoint Shield Solutions"
          style={{ width: 50, margin: '0 18px 0 24px' }}
        />
        <span
          className="dashboard-logo"
          style={{
            fontSize: 32,
            color: '#2471a3',
            fontWeight: 700,
            fontFamily: "'Segoe UI', Helvetica, Arial, sans-serif",
            letterSpacing: 1,
            flex: 1
          }}
        >
          Endpoint Shield Solutions
        </span>
        <button
          onClick={logOut}
          style={{
            marginRight: 24,
            padding: '6px 14px',
            background: 'transparent',
            border: '1px solid #2471a3',
            color: '#2471a3',
            borderRadius: 6,
            cursor: 'pointer',
            fontWeight: 600
          }}
        >
          Log out
        </button>
      </div>

      {/* Alerts panel */}
      <div
        style={{
          background: '#fffbe6',
          border: '1px solid #b59a00',
          padding: 10,
          marginBottom: 16,
          borderRadius: 6
        }}
      >
        <b>Alerts Panel</b>
        <button
          style={{
            float: 'right',
            background: '#fffbe6',
            border: 'none',
            color: '#b59a00',
            cursor: 'pointer',
            fontWeight: 600
          }}
          onClick={handleDismissAlerts}
        >
          Dismiss all
        </button>
        <ul style={{ margin: 0, paddingLeft: 20, paddingTop: 6 }}>
          {alerts.length === 0 && <li>No alerts</li>}
          {alerts.map(alert => (
            <li key={alert.key}>{alert.message}</li>
          ))}
        </ul>
      </div>

      {notice && (
        <div
          style={{
            background: '#ffeaea',
            border: '1px solid #e74c3c',
            padding: 10,
            marginBottom: 16,
            borderRadius: 6,
            color: '#a12626',
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            gap: 12
          }}
        >
          <span>{notice}</span>
          <button
            onClick={() => setNotice(null)}
            style={{
              background: 'transparent',
              border: 0,
              color: '#a12626',
              cursor: 'pointer',
              fontWeight: 700
            }}
          >
            ×
          </button>
        </div>
      )}

      {error && (
        <div
          style={{
            background: '#ffd6d6',
            border: '1px solid #e74c3c',
            padding: 10,
            marginBottom: 16,
            borderRadius: 6,
            color: '#a12626'
          }}
        >
          {error}
        </div>
      )}

      {/* Search + bulk actions */}
      <div style={{ display: 'flex', gap: 8, alignItems: 'center', marginBottom: 16, flexWrap: 'wrap' }}>
        <input
          value={search}
          onChange={e => setSearch(e.target.value)}
          placeholder="Search by hostname, IP, or OS"
          style={{ ...inputStyle, flex: 1, minWidth: 220 }}
        />
        <button
          onClick={handleBulkDelete}
          disabled={selected.length === 0}
          style={{
            padding: '7px 16px',
            background: selected.length === 0 ? '#ccc' : '#e74c3c',
            color: '#fff',
            border: 0,
            borderRadius: 6,
            fontWeight: 600,
            cursor: selected.length === 0 ? 'not-allowed' : 'pointer'
          }}
        >
          Delete Selected ({selected.length})
        </button>
      </div>

      {/* Add Device Form */}
      <form
        className="dashboard-form"
        onSubmit={handleAddDevice}
        style={{
          marginBottom: 24,
          display: 'flex',
          gap: 8,
          flexWrap: 'wrap',
          background: '#e8f0fd',
          padding: 14,
          borderRadius: 10
        }}
      >
        <input
          value={newDevice.hostname}
          onChange={e => setNewDevice({ ...newDevice, hostname: e.target.value })}
          placeholder="Hostname"
          required
          style={inputStyle}
        />
        <input
          value={newDevice.ip}
          onChange={e => setNewDevice({ ...newDevice, ip: e.target.value })}
          placeholder="IP"
          required
          style={inputStyle}
        />
        <input
          value={newDevice.cpu}
          onChange={e => setNewDevice({ ...newDevice, cpu: e.target.value })}
          placeholder="CPU"
          style={inputStyle}
        />
        <input
          value={newDevice.ram}
          onChange={e => setNewDevice({ ...newDevice, ram: e.target.value })}
          placeholder="RAM"
          style={inputStyle}
        />
        <input
          value={newDevice.disk}
          onChange={e => setNewDevice({ ...newDevice, disk: e.target.value })}
          placeholder="Disk"
          style={inputStyle}
        />
        <input
          value={newDevice.os}
          onChange={e => setNewDevice({ ...newDevice, os: e.target.value })}
          placeholder="OS"
          style={inputStyle}
        />
        <input
          value={newDevice.location}
          onChange={e => setNewDevice({ ...newDevice, location: e.target.value })}
          placeholder="Location"
          style={inputStyle}
        />
        <input
          value={newDevice.notes}
          onChange={e => setNewDevice({ ...newDevice, notes: e.target.value })}
          placeholder="Notes"
          style={inputStyle}
        />
        <button
          type="submit"
          style={{
            padding: '7px 18px',
            background: '#2471a3',
            color: '#fff',
            border: 0,
            borderRadius: 6,
            fontWeight: 600,
            cursor: 'pointer'
          }}
        >
          Add Device
        </button>
      </form>

      {/* Devices Table */}
      {loading && devices.length === 0 ? (
        <p>Loading devices…</p>
      ) : (
        <table style={{ width: '100%', borderCollapse: 'collapse' }}>
          <thead>
            <tr style={{ textAlign: 'left', borderBottom: '2px solid #dbe9f7' }}>
              <th style={{ padding: 8 }}>
                <input
                  type="checkbox"
                  checked={selected.length > 0 && selected.length === filteredDevices.length}
                  onChange={e => handleSelectAll(e.target.checked)}
                />
              </th>
              <th style={{ padding: 8 }}>Hostname</th>
              <th style={{ padding: 8 }}>IP</th>
              <th style={{ padding: 8 }}>CPU</th>
              <th style={{ padding: 8 }}>RAM</th>
              <th style={{ padding: 8 }}>Disk</th>
              <th style={{ padding: 8 }}>OS</th>
              <th style={{ padding: 8 }}>Location</th>
              <th style={{ padding: 8 }}>Notes</th>
              <th style={{ padding: 8 }}>Last Seen</th>
              <th style={{ padding: 8 }}>Status</th>
              <th style={{ padding: 8 }}>Actions</th>
            </tr>
          </thead>
          <tbody>
            {filteredDevices.length === 0 && (
              <tr>
                <td colSpan={12} style={{ padding: 16, textAlign: 'center', color: '#888' }}>
                  No devices found.
                </td>
              </tr>
            )}
            {filteredDevices.map(device => {
              const { status, color, icon, rowColor } = getStatus(device.last_seen);
              return (
                <tr
                  key={device.hostname}
                  style={{ backgroundColor: rowColor, transition: 'background 0.25s' }}
                >
                  <td style={{ padding: 8, borderBottom: '1px solid #eef4fa' }}>
                    <input
                      type="checkbox"
                      checked={selected.includes(device.hostname)}
                      onChange={e => handleToggleSelect(device.hostname, e.target.checked)}
                    />
                  </td>
                  <td style={{ padding: 8, borderBottom: '1px solid #eef4fa' }}>{device.hostname}</td>
                  <td style={{ padding: 8, borderBottom: '1px solid #eef4fa' }}>{device.ip}</td>
                  <td style={{ padding: 8, borderBottom: '1px solid #eef4fa' }}>{device.cpu}</td>
                  <td style={{ padding: 8, borderBottom: '1px solid #eef4fa' }}>{device.ram}</td>
                  <td style={{ padding: 8, borderBottom: '1px solid #eef4fa' }}>{device.disk}</td>
                  <td style={{ padding: 8, borderBottom: '1px solid #eef4fa' }}>{device.os}</td>
                  <td style={{ padding: 8, borderBottom: '1px solid #eef4fa' }}>{device.location}</td>
                  <td style={{ padding: 8, borderBottom: '1px solid #eef4fa' }}>{device.notes}</td>
                  <td style={{ padding: 8, borderBottom: '1px solid #eef4fa' }}>
                    {device.last_seen ? dayjs(device.last_seen).format('YYYY-MM-DD HH:mm:ss') : 'Never'}
                  </td>
                  <td style={{ padding: 8, borderBottom: '1px solid #eef4fa' }}>
                    <span style={{ color, fontWeight: 'bold', fontSize: 18, marginRight: 4 }}>{icon}</span>
                    <span style={{ color, fontWeight: 'bold' }}>{status}</span>
                  </td>
                  <td style={{ padding: 8, borderBottom: '1px solid #eef4fa' }}>
                    <button
                      onClick={() => setEditDevice(device)}
                      style={{
                        color: '#fff',
                        background: '#2471a3',
                        border: 0,
                        padding: '5px 13px',
                        borderRadius: 6,
                        cursor: 'pointer',
                        fontWeight: 500,
                        marginRight: 6
                      }}
                    >
                      Edit
                    </button>
                    <button
                      onClick={() => handleDeleteDevice(device.hostname)}
                      style={{
                        color: '#fff',
                        background: '#e74c3c',
                        border: 0,
                        padding: '5px 13px',
                        borderRadius: 6,
                        cursor: 'pointer',
                        fontWeight: 500
                      }}
                    >
                      Delete
                    </button>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      )}

      {/* Edit Device Form */}
      {editDevice && (
        <form
          onSubmit={async e => {
            e.preventDefault();
            try {
              const res = await fetch(
                `${API_URL}/devices/${encodeURIComponent(editDevice.hostname)}`,
                {
                  method: 'PUT',
                  headers: authHeaders(token, { 'Content-Type': 'application/json' }),
                  body: JSON.stringify(editDevice)
                }
              );
              if (!res.ok) {
                // Leave the form open so the edit isn't lost.
                setNotice(await errorMessage(res, 'Could not save the device'));
                return;
              }
              setEditDevice(null);
              setNotice(null);
              fetchDevices();
            } catch (err) {
              setError('Could not reach the device API. Is the backend running?');
            }
          }}
          style={{
            background: '#f6fbff',
            borderRadius: 10,
            padding: 18,
            marginTop: 18,
            marginBottom: 18,
            display: 'flex',
            flexDirection: 'column',
            gap: 10,
            boxShadow: '0 1px 6px #b3c8e6'
          }}
        >
          <h3 style={{ color: '#2471a3', fontWeight: 600, marginBottom: 8 }}>
            Edit Device: {editDevice.hostname}
          </h3>
          <input
            value={editDevice.ip}
            onChange={e => setEditDevice({ ...editDevice, ip: e.target.value })}
            placeholder="IP"
            style={inputStyle}
          />
          <input
            value={editDevice.cpu}
            onChange={e => setEditDevice({ ...editDevice, cpu: e.target.value })}
            placeholder="CPU"
            style={inputStyle}
          />
          <input
            value={editDevice.ram}
            onChange={e => setEditDevice({ ...editDevice, ram: e.target.value })}
            placeholder="RAM"
            style={inputStyle}
          />
          <input
            value={editDevice.disk}
            onChange={e => setEditDevice({ ...editDevice, disk: e.target.value })}
            placeholder="Disk"
            style={inputStyle}
          />
          <input
            value={editDevice.os}
            onChange={e => setEditDevice({ ...editDevice, os: e.target.value })}
            placeholder="OS"
            style={inputStyle}
          />
          <input
            value={editDevice.location}
            onChange={e => setEditDevice({ ...editDevice, location: e.target.value })}
            placeholder="Location"
            style={inputStyle}
          />
          <input
            value={editDevice.notes}
            onChange={e => setEditDevice({ ...editDevice, notes: e.target.value })}
            placeholder="Notes"
            style={inputStyle}
          />
          <div style={{ marginTop: 12 }}>
            <button
              type="submit"
              style={{
                padding: '6px 22px',
                background: '#2471a3',
                color: '#fff',
                border: 0,
                borderRadius: 6,
                fontWeight: 600,
                fontSize: 16,
                cursor: 'pointer',
                marginRight: 8
              }}
            >
              Save
            </button>
            <button
              type="button"
              style={{
                padding: '6px 18px',
                background: '#aaa',
                color: '#fff',
                border: 0,
                borderRadius: 6,
                fontWeight: 600,
                fontSize: 16,
                cursor: 'pointer'
              }}
              onClick={() => setEditDevice(null)}
            >
              Cancel
            </button>
          </div>
        </form>
      )}
    </div>
  );
}

export default App;
