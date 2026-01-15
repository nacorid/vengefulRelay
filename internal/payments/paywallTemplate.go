package payments

const customPaywallHTML = `<!DOCTYPE html>
<html>
<head>
    <title>Payment Required</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <!-- Include the missing script here -->
    <script src="https://pay.coinbase.com/v1/x402.js"></script>
    <style>
        /* Your styles (or copy the default ones from your log) */
        body { font-family: system-ui, sans-serif; background: #f5f5f5; padding: 20px; }
        .container { max-width: 600px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Payment Required</h1>
        <div id="payment-widget" 
            data-requirements='{{.Requirements}}'
            data-cdp-client-key="{{.CDPClientKey}}"
            data-app-name="{{.AppName}}"
            data-testnet="{{.Testnet}}">
            <p>Loading payment widget...</p>
        </div>
    </div>
</body>
</html>`
