import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import App from './App';

// Real timers throughout - waitFor() below polls with a real setTimeout
// internally, which hangs forever under jest.useFakeTimers() unless
// something explicitly advances them. The 10s polling interval
// fetchDevices() sets up never fires within a test's real runtime, so
// there's nothing for fake timers to protect against here.
//
// Generous timeout: this is tuned for CI/dev machines under normal load,
// not the 5s Jest default - drop it back down if these ever run somewhere
// less resource-constrained than they were written against.
jest.setTimeout(30000);
const WAIT_OPTS = { timeout: 20000 };

beforeEach(() => {
  sessionStorage.clear();
  global.fetch = jest.fn(() =>
    Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve([]) })
  );
});

afterEach(() => {
  jest.restoreAllMocks();
});

test('shows the login form when there is no session', () => {
  render(<App />);
  expect(screen.getByText(/Dental MSP Device Dashboard/i)).toBeInTheDocument();
  expect(screen.getByPlaceholderText(/Username/i)).toBeInTheDocument();
  expect(screen.getByPlaceholderText(/Password/i)).toBeInTheDocument();
  // Logging in is the only thing that should hit the network from here.
  expect(global.fetch).not.toHaveBeenCalled();
});

test('logs in and then loads the device list', async () => {
  global.fetch = jest.fn(url => {
    if (String(url).endsWith('/api/login')) {
      return Promise.resolve({
        ok: true,
        json: () => Promise.resolve({ access_token: 'test-token', token_type: 'bearer' })
      });
    }
    return Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve([]) });
  });

  render(<App />);
  fireEvent.change(screen.getByPlaceholderText(/Username/i), { target: { value: 'admin' } });
  fireEvent.change(screen.getByPlaceholderText(/Password/i), { target: { value: 'password' } });
  fireEvent.click(screen.getByRole('button', { name: /Log in/i }));

  await waitFor(() => expect(screen.getByText(/No devices found/i)).toBeInTheDocument(), WAIT_OPTS);
  expect(screen.getByText(/No alerts/i)).toBeInTheDocument();
  expect(sessionStorage.getItem('msp_dashboard_token')).toBe('test-token');
});

test('an existing session skips the login form', async () => {
  sessionStorage.setItem('msp_dashboard_token', 'existing-token');
  render(<App />);
  await waitFor(() => expect(screen.getByText(/No devices found/i)).toBeInTheDocument(), WAIT_OPTS);
  expect(screen.queryByPlaceholderText(/Username/i)).not.toBeInTheDocument();
});
