<?php
// --- SETUP & SECURITY ---
// --- Created By NCMS ---
error_reporting(0); // Use E_ALL for debugging, 0 for production
session_start();

if (!file_exists('config.php')) {
    header('Location: install.php');
    exit;
}
require_once 'config.php';

// --- DATABASE CONNECTION ---
$conn = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME);
if ($conn->connect_error) {
    die("Database Connection Failed. Please check your config.php file. Error: " . $conn->connect_error);
}

// --- MAINTENANCE MODE CHECK ---
$settings_res = $conn->query("SELECT * FROM settings");
$settings = [];
if ($settings_res) {
    while ($row = $settings_res->fetch_assoc()) {
        $settings[$row['setting_key']] = $row['setting_value'];
    }
}
if (($settings['maintenance_mode'] ?? 'off') === 'on' && (!isset($_SESSION['role']) || $_SESSION['role'] !== 'admin')) {
    die('<!DOCTYPE html><html><head><title>Maintenance</title><script src="https://cdn.tailwindcss.com"></script></head><body class="bg-gray-900 text-white flex items-center justify-center h-screen"><div class="text-center"><h1 class="text-4xl font-bold text-sky-400">Under Maintenance</h1><p class="mt-4 text-lg text-gray-300">' . htmlspecialchars($settings['maintenance_message'] ?? 'We are currently performing scheduled maintenance.') . '</p></div></body></html>');
}


// --- GLOBAL VARIABLES & LOGIC ROUTING ---
$page = $_GET['page'] ?? 'dashboard';
$error = $_SESSION['error_message'] ?? '';
$success = $_SESSION['success_message'] ?? '';
unset($_SESSION['error_message'], $_SESSION['success_message']);

// --- FORM SUBMISSION HANDLING (CONTROLLER LOGIC) ---
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // --- Registration Logic ---
    if (isset($_POST['register'])) {
        $email = trim($_POST['email']); $full_name = trim($_POST['full_name']);
        $company_name = trim($_POST['company_name']); $address = trim($_POST['address']);
        $password = $_POST['password']; $password_confirm = $_POST['password_confirm'];

        if (strlen($password) < 8) { $error = 'Password must be at least 8 characters long.';
        } elseif ($password !== $password_confirm) { $error = 'Passwords do not match.';
        } elseif (filter_var($email, FILTER_VALIDATE_EMAIL) === false) { $error = 'Invalid email address.';
        } elseif (empty($full_name)) { $error = 'Full name is required.';
        } else {
            $stmt = $conn->prepare("SELECT id FROM users WHERE email = ?");
            $stmt->bind_param("s", $email); $stmt->execute();
            if ($stmt->get_result()->num_rows > 0) {
                $error = 'An account with this email already exists.';
            } else {
                $hashed_password = password_hash($password, PASSWORD_DEFAULT);
                $stmt = $conn->prepare("INSERT INTO users (email, password, full_name, company_name, address) VALUES (?, ?, ?, ?, ?)");
                $stmt->bind_param("sssss", $email, $hashed_password, $full_name, $company_name, $address);
                if ($stmt->execute()) {
                    $_SESSION['success_message'] = 'Registration successful! Please log in.';
                    header('Location: index.php?page=login'); exit;
                } else { $error = 'Registration failed. Please try again.'; }
            }
            $stmt->close();
        }
    }
    // --- Login Logic ---
    elseif (isset($_POST['login'])) {
        $email = $_POST['email']; $password = $_POST['password'];
        $stmt = $conn->prepare("SELECT id, password, role, full_name FROM users WHERE email = ?");
        $stmt->bind_param("s", $email); $stmt->execute(); $stmt->store_result();
        if ($stmt->num_rows > 0) {
            $stmt->bind_result($id, $hashed_password, $role, $full_name); $stmt->fetch();
            if (password_verify($password, $hashed_password)) {
                $_SESSION['user_id'] = $id; $_SESSION['email'] = $email;
                $_SESSION['role'] = $role; $_SESSION['full_name'] = $full_name;
                header('Location: index.php?page=dashboard'); exit;
            } else { $error = 'Invalid credentials.'; }
        } else { $error = 'Invalid credentials.'; }
        $stmt->close();
    }
     // --- Profile Update Logic ---
    elseif (isset($_POST['update_profile'])) {
        if (!isset($_SESSION['user_id'])) { header('Location: index.php?page=login'); exit; }
        $user_id = $_SESSION['user_id'];
        $full_name = trim($_POST['full_name']); $email = trim($_POST['email']);
        $company_name = trim($_POST['company_name']); $address = trim($_POST['address']);
        $password = $_POST['password'];

        if (!empty($password)) {
            if (strlen($password) < 8) {
                $_SESSION['error_message'] = 'New password must be at least 8 characters long.';
                header('Location: index.php?page=profile'); exit;
            }
            $hashed_password = password_hash($password, PASSWORD_DEFAULT);
            $stmt = $conn->prepare("UPDATE users SET full_name = ?, email = ?, company_name = ?, address = ?, password = ? WHERE id = ?");
            $stmt->bind_param("sssssi", $full_name, $email, $company_name, $address, $hashed_password, $user_id);
        } else {
            $stmt = $conn->prepare("UPDATE users SET full_name = ?, email = ?, company_name = ?, address = ? WHERE id = ?");
            $stmt->bind_param("ssssi", $full_name, $email, $company_name, $address, $user_id);
        }
        
        if($stmt->execute()){ $_SESSION['success_message'] = "Your profile has been updated successfully."; } else { $_SESSION['error_message'] = "Failed to update profile."; }
        $stmt->close(); header('Location: index.php?page=profile'); exit;
    }
    // --- Place Order Logic ---
    elseif (isset($_POST['place_order'])) {
        if (!isset($_SESSION['user_id'])) { header('Location: index.php?page=login'); exit; }
        $product_id = intval($_POST['product_id']); $user_id = $_SESSION['user_id'];
        $stmt = $conn->prepare("SELECT * FROM products WHERE id = ?"); $stmt->bind_param("i", $product_id); $stmt->execute();
        $product = $stmt->get_result()->fetch_assoc(); $stmt->close();
        if ($product) {
            $next_due_date = date('Y-m-d', strtotime('+1 month'));
            $stmt_order = $conn->prepare("INSERT INTO client_services (user_id, product_id, next_due_date) VALUES (?, ?, ?)");
            $stmt_order->bind_param("iis", $user_id, $product_id, $next_due_date);
            if ($stmt_order->execute()) {
                $client_service_id = $stmt_order->insert_id;
                $issue_date = date('Y-m-d'); $due_date = date('Y-m-d', strtotime('+14 days'));
                $description = "First invoice for " . $product['name']; $amount = $product['price'];
                $stmt_invoice = $conn->prepare("INSERT INTO invoices (user_id, client_service_id, description, amount, issue_date, due_date) VALUES (?, ?, ?, ?, ?, ?)");
                $stmt_invoice->bind_param("iisdss", $user_id, $client_service_id, $description, $amount, $issue_date, $due_date);
                $stmt_invoice->execute(); $stmt_invoice->close();
                $_SESSION['success_message'] = "Order placed successfully! Invoice #".$conn->insert_id." has been generated.";
                header('Location: index.php?page=invoices'); exit;
            } else { $error = "Failed to place order."; }
            $stmt_order->close();
        } else { $error = "Invalid product selected."; }
    }
    // --- Open Ticket Logic ---
    elseif (isset($_POST['open_ticket'])) {
        if (!isset($_SESSION['user_id'])) { header('Location: index.php?page=login'); exit; }
        $subject = trim($_POST['subject']); $department = trim($_POST['department']); $priority = trim($_POST['priority']); $message = trim($_POST['message']);
        $stmt = $conn->prepare("INSERT INTO tickets (user_id, subject, department, priority) VALUES (?, ?, ?, ?)");
        $stmt->bind_param("isss", $_SESSION['user_id'], $subject, $department, $priority);
        if ($stmt->execute()) {
            $ticket_id = $stmt->insert_id;
            $stmt_reply = $conn->prepare("INSERT INTO ticket_replies (ticket_id, user_id, message) VALUES (?, ?, ?)");
            $stmt_reply->bind_param("iis", $ticket_id, $_SESSION['user_id'], $message);
            $stmt_reply->execute(); $stmt_reply->close();
            $_SESSION['success_message'] = "Support ticket #{$ticket_id} has been opened.";
            header('Location: index.php?page=view_ticket&id=' . $ticket_id); exit;
        } else { $error = "Failed to open ticket."; }
        $stmt->close();
    }
    // --- Post Reply Logic ---
    elseif (isset($_POST['post_reply'])) {
        if (!isset($_SESSION['user_id'])) { header('Location: index.php?page=login'); exit; }
        $ticket_id = intval($_POST['ticket_id']); $message = trim($_POST['message']);
        $verify_stmt = $conn->prepare("SELECT user_id FROM tickets WHERE id = ?"); $verify_stmt->bind_param("i", $ticket_id); $verify_stmt->execute();
        $ticket = $verify_stmt->get_result()->fetch_assoc(); $verify_stmt->close();
        if ($ticket && $ticket['user_id'] == $_SESSION['user_id']) {
            $stmt_reply = $conn->prepare("INSERT INTO ticket_replies (ticket_id, user_id, message) VALUES (?, ?, ?)");
            $stmt_reply->bind_param("iis", $ticket_id, $_SESSION['user_id'], $message);
            $stmt_reply->execute(); $stmt_reply->close();
            $conn->query("UPDATE tickets SET status = 'Open', last_reply=NOW() WHERE id = $ticket_id");
            $_SESSION['success_message'] = "Your reply has been posted.";
            header('Location: index.php?page=view_ticket&id=' . $ticket_id); exit;
        }
    }
}

// --- Redirect non-logged-in users ---
if (!isset($_SESSION['user_id']) && !in_array($page, ['login', 'register'])) {
    $page = 'login';
}

// --- Helper Functions for UI ---
function get_status_color_class($status) { $map = ['active' => 'bg-green-500', 'paid' => 'bg-green-500', 'answered' => 'bg-sky-500', 'open' => 'bg-yellow-500', 'pending' => 'bg-yellow-500', 'unpaid' => 'bg-yellow-500', 'suspended' => 'bg-red-500', 'terminated' => 'bg-red-700', 'cancelled' => 'bg-gray-500', 'closed' => 'bg-gray-600', 'refunded' => 'bg-purple-500']; return $map[strtolower($status)] ?? 'bg-gray-500'; }
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>Client Panel - NordCMS</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <style> body { background-color: #0d1117; font-family: 'Inter', sans-serif; } .aurora-bg { background: radial-gradient(ellipse at top, transparent 40%, #0d1117), linear-gradient(135deg, #0d1117 0%, #0c2a3a 30%, #093642 70%, #0d1117 100%); background-size: 200% 200%; animation: aurora 15s ease infinite; } @keyframes aurora { 0% { background-position: 0% 50%; } 50% { background-position: 100% 50%; } 100% { background-position: 0% 50%; } } .printable-area { background-color: white; color: black; } @media print { body * { visibility: hidden; } .printable-area, .printable-area * { visibility: visible; } .printable-area { position: absolute; left: 0; top: 0; width: 100%; } .no-print { display: none; } } </style>
</head>
<body class="text-white aurora-bg min-h-screen">
    <header class="bg-[#161b22]/50 backdrop-blur-sm sticky top-0 z-50 no-print">
        <div class="container mx-auto px-4 sm:px-6 lg:px-8">
            <div class="flex items-center justify-between h-24">
                <a href="index.php" class="flex items-center space-x-2"><span class="text-2xl font-black tracking-wider text-white">Nord</span><span class="text-2xl font-black tracking-wider text-sky-400">CMS</span><span class="text-xl font-semibold text-gray-400 pl-2">Client Panel</span></a>
                <?php if (isset($_SESSION['user_id'])): ?>
                <div class="flex items-center gap-4">
                    <?php if ($_SESSION['role'] === 'admin'): ?><a href="admin.php" class="text-sky-400 font-bold py-2 px-5 rounded-lg border-2 border-sky-700 hover:border-sky-400 transition-all">Admin Panel</a><?php endif; ?>
                    <a href="logout.php" class="text-white font-bold py-2 px-5 rounded-lg border-2 border-gray-700 hover:border-red-500 transition-all">Logout</a>
                </div>
                <?php endif; ?>
            </div>
        </div>
    </header>
    <main class="container mx-auto px-4 sm:px-6 lg:px-8 py-12">
        <?php if (!empty($error)): ?><div class="mb-6 p-4 bg-red-900/50 border border-red-500 text-red-300 rounded-lg no-print"><?php echo htmlspecialchars($error); ?></div><?php endif; ?>
        <?php if (!empty($success)): ?><div class="mb-6 p-4 bg-green-900/50 border border-green-500 text-green-300 rounded-lg no-print"><?php echo htmlspecialchars($success); ?></div><?php endif; ?>

        <?php if ($page === 'login'): ?>
            <div class="max-w-md mx-auto mt-16 bg-[#161b22]/80 p-8 rounded-xl shadow-2xl border border-gray-700"><h2 class="text-3xl font-black text-center text-sky-400">Client Login</h2><form method="POST" class="mt-8 space-y-6"><input type="hidden" name="login" value="1"><div><label for="email" class="block text-sm font-medium">Email</label><input type="email" name="email" id="email" class="mt-1 block w-full bg-[#0d1117] border border-gray-600 rounded-md py-2 px-3" required></div><div><label for="password" class="block text-sm font-medium">Password</label><input type="password" name="password" id="password" class="mt-1 block w-full bg-[#0d1117] border border-gray-600 rounded-md py-2 px-3" required></div><button type="submit" class="w-full bg-sky-600 text-white font-bold py-3 px-4 rounded-lg hover:bg-sky-700">Sign In</button></form><p class="text-center mt-6 text-gray-400">Don't have an account? <a href="index.php?page=register" class="font-semibold text-sky-400 hover:text-sky-300">Register here</a>.</p></div>
        <?php elseif ($page === 'register'): ?>
            <div class="max-w-md mx-auto mt-16 bg-[#161b22]/80 p-8 rounded-xl shadow-2xl border border-gray-700"><h2 class="text-3xl font-black text-center text-sky-400">Create an Account</h2><form method="POST" class="mt-8 space-y-6"><input type="hidden" name="register" value="1"><div class="grid grid-cols-1 md:grid-cols-2 gap-6"><div><label for="full_name" class="block text-sm font-medium">Full Name</label><input type="text" name="full_name" id="full_name" class="mt-1 block w-full bg-[#0d1117] border border-gray-600 rounded-md py-2 px-3" required></div><div><label for="company_name" class="block text-sm font-medium">Company Name (Optional)</label><input type="text" name="company_name" id="company_name" class="mt-1 block w-full bg-[#0d1117] border border-gray-600 rounded-md py-2 px-3"></div></div><div class="mt-6"><label for="address" class="block text-sm font-medium">Address (for Invoices)</label><textarea name="address" rows="3" class="mt-1 block w-full bg-[#0d1117] border border-gray-600 rounded-md p-3"></textarea></div><div class="mt-6"><label for="email" class="block text-sm font-medium">Email Address</label><input type="email" name="email" id="email" class="mt-1 block w-full bg-[#0d1117] border border-gray-600 rounded-md py-2 px-3" required></div><div class="mt-6 grid grid-cols-1 md:grid-cols-2 gap-6"><div><label for="password" class="block text-sm font-medium">Password (min. 8 characters)</label><input type="password" name="password" id="password" class="mt-1 block w-full bg-[#0d1117] border border-gray-600 rounded-md py-2 px-3" required></div><div><label for="password_confirm" class="block text-sm font-medium">Confirm Password</label><input type="password" name="password_confirm" id="password_confirm" class="mt-1 block w-full bg-[#0d1117] border border-gray-600 rounded-md py-2 px-3" required></div></div><button type="submit" class="mt-6 w-full bg-sky-600 text-white font-bold py-3 px-4 rounded-lg hover:bg-sky-700">Register</button></form><p class="text-center mt-6 text-gray-400">Already have an account? <a href="index.php?page=login" class="font-semibold text-sky-400 hover:text-sky-300">Login here</a>.</p></div>
        <?php elseif (isset($_SESSION['user_id'])): $user_id = $_SESSION['user_id']; ?>
            <div class="lg:flex lg:gap-8">
                <aside class="w-full lg:w-1/4 mb-8 lg:mb-0 no-print"><nav class="bg-[#161b22]/80 border border-gray-700 rounded-xl p-4 sticky top-28"><a href="index.php?page=dashboard" class="block py-2 px-4 rounded-md hover:bg-sky-500/10 font-semibold">Dashboard</a><a href="index.php?page=profile" class="block py-2 px-4 rounded-md hover:bg-sky-500/10 font-semibold">My Details</a><a href="index.php?page=services" class="block py-2 px-4 rounded-md hover:bg-sky-500/10 font-semibold">My Services</a><a href="index.php?page=order" class="block py-2 px-4 rounded-md hover:bg-sky-500/10 font-semibold">Order New Services</a><a href="index.php?page=invoices" class="block py-2 px-4 rounded-md hover:bg-sky-500/10 font-semibold">My Invoices</a><a href="index.php?page=tickets" class="block py-2 px-4 rounded-md hover:bg-sky-500/10 font-semibold">Support Tickets</a><a href="index.php?page=announcements" class="block py-2 px-4 rounded-md hover:bg-sky-500/10 font-semibold">Announcements</a></nav></aside>
                <div class="w-full lg:w-3/4">
                    <?php 
                        // --- Client-Side Page Renderer ---
                        switch($page) {
                            case 'services':
                                echo '<h1 class="text-3xl font-bold mb-8">Your Services</h1><div class="bg-[#161b22]/80 border border-gray-700 rounded-xl shadow-lg overflow-x-auto"><table class="w-full text-left"><thead class="bg-[#0d1117]/50"><tr><th class="p-4">Product</th><th class="p-4">Price</th><th class="p-4">Next Due Date</th><th class="p-4">Status</th><th class="p-4"></th></tr></thead><tbody class="divide-y divide-gray-800">';
                                $stmt = $conn->prepare("SELECT cs.id, p.name as product_name, p.price, cs.next_due_date, cs.status FROM client_services cs JOIN products p ON cs.product_id = p.id WHERE cs.user_id = ? ORDER BY cs.created_at DESC"); $stmt->bind_param("i", $user_id); $stmt->execute(); $result = $stmt->get_result();
                                if ($result->num_rows > 0) { while($row = $result->fetch_assoc()) echo "<tr><td class='p-4 font-bold'>".htmlspecialchars($row['product_name'])."</td><td class='p-4'>€".htmlspecialchars(number_format($row['price'], 2))."</td><td class='p-4'>".htmlspecialchars($row['next_due_date'])."</td><td class='p-4'><span class='px-2 py-1 text-xs font-bold rounded-full text-white ".get_status_color_class($row['status'])."'>".htmlspecialchars($row['status'])."</span></td><td class='p-4 text-right'><a href='index.php?page=view_service&id=".$row['id']."' class='font-semibold text-sky-400 hover:text-sky-300'>Manage</a></td></tr>"; } else { echo "<tr><td colspan='5' class='p-4 text-center text-gray-400'>You have no active services.</td></tr>"; } $stmt->close();
                                echo '</tbody></table></div>'; break;
                            case 'view_service':
                                $service_id = intval($_GET['id']); $stmt = $conn->prepare("SELECT cs.id, cs.status, cs.next_due_date, cs.created_at, p.name as product_name, p.description, p.price, p.billing_cycle FROM client_services cs JOIN products p ON cs.product_id = p.id WHERE cs.id = ? AND cs.user_id = ?"); $stmt->bind_param("ii", $service_id, $user_id); $stmt->execute(); $service = $stmt->get_result()->fetch_assoc(); $stmt->close();
                                if($service) {
                                    echo '<h1 class="text-3xl font-bold mb-2">Manage: '.htmlspecialchars($service['product_name']).'</h1><div class="mb-8"><a href="index.php?page=services" class="text-sm text-sky-400 hover:text-sky-300">&larr; Back to My Services</a></div>';
                                    echo '<div class="bg-[#161b22]/80 p-8 rounded-xl border border-gray-700 grid md:grid-cols-2 gap-6">';
                                    echo '<div><p class="text-gray-400 text-sm font-bold">Product</p><p class="text-lg">'.htmlspecialchars($service['product_name']).'</p></div>';
                                    echo '<div><p class="text-gray-400 text-sm font-bold">Status</p><p><span class="px-2 py-1 text-xs font-bold rounded-full text-white '.get_status_color_class($service['status']).'">'.htmlspecialchars($service['status']).'</span></p></div>';
                                    echo '<div><p class="text-gray-400 text-sm font-bold">Order Date</p><p class="text-lg">'.date('F j, Y', strtotime($service['created_at'])).'</p></div>';
                                    echo '<div><p class="text-gray-400 text-sm font-bold">Next Due Date</p><p class="text-lg">'.date('F j, Y', strtotime($service['next_due_date'])).'</p></div>';
                                    echo '<div class="md:col-span-2"><p class="text-gray-400 text-sm font-bold">Price</p><p class="text-lg">€'.htmlspecialchars(number_format($service['price'], 2)).' '.htmlspecialchars($service['billing_cycle']).'</p></div>';
                                    echo '</div>';
                                } else { echo '<p>Service not found.</p>'; }
                                break;
                            case 'order':
                                echo '<h1 class="text-3xl font-bold mb-8">Order New Service</h1><div class="grid md:grid-cols-2 lg:grid-cols-3 gap-8">';
                                $products_res = $conn->query("SELECT * FROM products");
                                while($product = $products_res->fetch_assoc()) { echo '<div class="bg-[#161b22]/80 p-6 rounded-xl border border-gray-700 flex flex-col justify-between"><div><h3 class="text-xl font-bold text-sky-400">'.htmlspecialchars($product['name']).'</h3><p class="text-gray-400 mt-2 min-h-[60px]">'.htmlspecialchars($product['description']).'</p></div><div class="mt-6"><p class="text-3xl font-black">€'.htmlspecialchars(number_format($product['price'], 2)).'</p><p class="text-gray-500">/ '.htmlspecialchars($product['billing_cycle']).'</p><form method="POST"><input type="hidden" name="product_id" value="'.$product['id'].'"><button type="submit" name="place_order" class="mt-4 w-full bg-sky-600 font-bold py-2 px-4 rounded-lg hover:bg-sky-700">Order Now</button></form></div></div>'; }
                                echo '</div>'; break;
                            case 'invoices':
                                echo '<h1 class="text-3xl font-bold mb-8">Your Invoices</h1><div class="bg-[#161b22]/80 border border-gray-700 rounded-xl shadow-lg overflow-x-auto"><table class="w-full text-left"><thead class="bg-[#0d1117]/50"><tr><th class="p-4">Invoice #</th><th class="p-4">Date Issued</th><th class="p-4">Total</th><th class="p-4">Status</th><th class="p-4"></th></tr></thead><tbody class="divide-y divide-gray-800">';
                                $stmt = $conn->prepare("SELECT id, issue_date, amount, status FROM invoices WHERE user_id = ? ORDER BY issue_date DESC"); $stmt->bind_param("i", $user_id); $stmt->execute(); $result = $stmt->get_result();
                                if ($result->num_rows > 0) { while($row = $result->fetch_assoc()) echo "<tr><td class='p-4 font-bold'>#".htmlspecialchars($row['id'])."</td><td class='p-4'>".htmlspecialchars($row['issue_date'])."</td><td class='p-4'>€".htmlspecialchars(number_format($row['amount'], 2))."</td><td class='p-4'><span class='px-2 py-1 text-xs font-bold rounded-full text-white ".get_status_color_class($row['status'])."'>".htmlspecialchars($row['status'])."</span></td><td class='p-4 text-right'><a href='index.php?page=view_invoice&id=".$row['id']."' class='font-semibold text-sky-400 hover:text-sky-300'>View</a></td></tr>"; } else { echo "<tr><td colspan='5' class='p-4 text-center text-gray-400'>You have no invoices.</td></tr>"; } $stmt->close();
                                echo '</tbody></table></div>'; break;
                            case 'view_invoice':
                                $invoice_id = intval($_GET['id']); $stmt = $conn->prepare("SELECT i.*, u.full_name, u.company_name, u.address FROM invoices i JOIN users u ON i.user_id = u.id WHERE i.id = ? AND i.user_id = ?"); $stmt->bind_param("ii", $invoice_id, $user_id); $stmt->execute(); $invoice = $stmt->get_result()->fetch_assoc(); $stmt->close();
                                $settings_res = $conn->query("SELECT * FROM settings"); $settings = []; while($row = $settings_res->fetch_assoc()) { $settings[$row['setting_key']] = $row['setting_value']; }
                                if ($invoice): echo '<div id="invoice-container" class="max-w-4xl mx-auto bg-white text-black p-10 rounded-xl shadow-2xl printable-area"><div class="flex justify-between items-start"><div class="text-left"><h2 class="text-4xl font-black">INVOICE</h2><p class="text-gray-500">#'.htmlspecialchars($invoice['id']).'</p></div><div class="text-right"><p class="text-2xl font-black" style="color:'.htmlspecialchars($settings['primary_color'] ?? '#38bdf8').';">'.htmlspecialchars($settings['company_name']).'</p><p class="text-gray-600 text-sm">'.nl2br(htmlspecialchars($settings['company_address'])).'</p></div></div><div class="mt-12 grid grid-cols-2 gap-8"><div><p class="font-bold text-gray-500">BILLED TO</p><p class="text-lg font-semibold">'.htmlspecialchars($invoice['full_name']).'</p><p class="text-gray-700">'.htmlspecialchars($invoice['company_name']).'</p><p class="text-gray-700 whitespace-pre-wrap">'.htmlspecialchars($invoice['address']).'</p></div><div class="text-right"><p class="font-bold text-gray-500">Issue Date:</p><p class="mb-4">'.htmlspecialchars($invoice['issue_date']).'</p><p class="font-bold text-gray-500">Due Date:</p><p>'.htmlspecialchars($invoice['due_date']).'</p></div></div><div class="mt-12"><table class="w-full text-left"><thead><tr class="bg-gray-100"><th class="p-3">Description</th><th class="p-3 text-right">Amount</th></tr></thead><tbody><tr class="border-b"><td class="p-3">'.nl2br(htmlspecialchars($invoice['description'])).'</td><td class="p-3 text-right">€'.htmlspecialchars(number_format($invoice['amount'], 2)).'</td></tr></tbody></table></div><div class="mt-8 flex justify-end"><div class="w-full max-w-xs space-y-4"><div class="flex justify-between text-lg"><span class="text-gray-600">Subtotal:</span><span>€'.htmlspecialchars(number_format($invoice['amount'], 2)).'</span></div><div class="flex justify-between text-2xl font-bold border-t pt-4 mt-4"><span class="text-black">Total:</span><span style="color:'.htmlspecialchars($settings['primary_color'] ?? '#38bdf8').';">€'.htmlspecialchars(number_format($invoice['amount'], 2)).'</span></div></div></div></div><div class="no-print mt-8 flex flex-col md:flex-row justify-between items-center gap-4"><button onclick="window.print()" class="text-gray-400 hover:text-white font-semibold">Download PDF</button>';
                                    if ($invoice['status'] === 'Unpaid') { echo '<div class="flex flex-wrap gap-2">'; $paypal_enabled = !empty($settings['paypal_email']); $stripe_enabled = !empty($settings['stripe_pk']); $crypto_enabled = !empty($settings['crypto_address']); if($stripe_enabled){ echo '<button class="bg-indigo-600 text-white font-bold py-3 px-6 rounded-lg hover:bg-indigo-500">Pay with Stripe</button>'; } else { echo '<button class="bg-gray-500 text-white font-bold py-3 px-6 rounded-lg cursor-not-allowed" disabled>Stripe (Not Configured)</button>'; } if($paypal_enabled){ echo '<button class="bg-blue-600 text-white font-bold py-3 px-6 rounded-lg hover:bg-blue-500">Pay with PayPal</button>'; } else { echo '<button class="bg-gray-500 text-white font-bold py-3 px-6 rounded-lg cursor-not-allowed" disabled>PayPal (Not Configured)</button>'; } if($crypto_enabled){ echo '<button class="bg-yellow-500 text-black font-bold py-3 px-6 rounded-lg hover:bg-yellow-400">Pay with Crypto</button>'; } else { echo '<button class="bg-gray-500 text-white font-bold py-3 px-6 rounded-lg cursor-not-allowed" disabled>Crypto (Not Configured)</button>'; } echo '</div>'; } else { echo '<p class="text-2xl font-bold">Status: <span class="px-3 py-1 rounded-full text-white '.get_status_color_class($invoice['status']).'">'.htmlspecialchars($invoice['status']).'</span></p>'; }
                                    echo '</div>'; else: echo "<p>Invoice not found.</p>"; endif; break;
                            case 'tickets':
                                echo '<div class="flex justify-between items-center mb-8"><h1 class="text-3xl font-bold">Support Tickets</h1><a href="index.php?page=open_ticket" class="bg-sky-600 font-bold py-2 px-6 rounded-lg hover:bg-sky-700">Open New Ticket</a></div><div class="bg-[#161b22]/80 border border-gray-700 rounded-xl shadow-lg overflow-x-auto"><table class="w-full text-left"><thead class="bg-[#0d1117]/50"><tr><th class="p-4">ID</th><th class="p-4">Subject</th><th class="p-4">Status</th><th class="p-4">Last Updated</th><th class="p-4"></th></tr></thead><tbody class="divide-y divide-gray-800">';
                                $stmt = $conn->prepare("SELECT id, subject, status, last_reply FROM tickets WHERE user_id = ? ORDER BY last_reply DESC"); $stmt->bind_param("i", $user_id); $stmt->execute(); $result = $stmt->get_result();
                                if ($result->num_rows > 0) { while($row = $result->fetch_assoc()) echo "<tr><td class='p-4'>#".htmlspecialchars($row['id'])."</td><td class='p-4 font-bold'>".htmlspecialchars($row['subject'])."</td><td class='p-4'><span class='px-2 py-1 text-xs font-bold rounded-full text-white ".get_status_color_class($row['status'])."'>".htmlspecialchars($row['status'])."</span></td><td class='p-4'>".htmlspecialchars($row['last_reply'])."</td><td class='p-4 text-right'><a href='index.php?page=view_ticket&id=".$row['id']."' class='font-semibold text-sky-400 hover:text-sky-300'>View</a></td></tr>"; } else { echo "<tr><td colspan='5' class='p-4 text-center text-gray-400'>You have no support tickets.</td></tr>"; } $stmt->close();
                                echo '</tbody></table></div>'; break;
                            case 'open_ticket':
                                echo '<h1 class="text-3xl font-bold mb-8">Open a New Support Ticket</h1><div class="bg-[#161b22]/80 p-8 rounded-xl border border-gray-700"><form method="POST"><input type="hidden" name="open_ticket" value="1"><div class="grid md:grid-cols-2 gap-6"><div class="md:col-span-2"><label for="subject" class="block text-sm font-medium">Subject</label><input type="text" name="subject" class="mt-1 block w-full bg-[#0d1117] border border-gray-600 rounded-md py-2 px-3" required></div><div><label for="department" class="block text-sm font-medium">Department</label><select name="department" class="mt-1 block w-full bg-[#0d1117] border border-gray-600 rounded-md py-2 px-3"><option>Technical Support</option><option>Billing</option><option>Sales</option></select></div><div><label for="priority" class="block text-sm font-medium">Priority</label><select name="priority" class="mt-1 block w-full bg-[#0d1117] border border-gray-600 rounded-md py-2 px-3"><option>Medium</option><option>High</option><option>Low</option></select></div><div class="md:col-span-2"><label for="message" class="block text-sm font-medium">Message</label><textarea name="message" rows="8" class="mt-1 block w-full bg-[#0d1117] border border-gray-600 rounded-md p-3" required></textarea></div></div><div class="mt-6 text-right"><button type="submit" class="bg-sky-600 font-bold py-2 px-6 rounded-lg hover:bg-sky-700">Submit Ticket</button></div></form></div>';
                                break;
                             case 'view_ticket':
                                $id = intval($_GET['id']); $stmt = $conn->prepare("SELECT t.* FROM tickets t WHERE t.id = ? AND t.user_id = ?"); $stmt->bind_param("ii", $id, $user_id); $stmt->execute(); $ticket = $stmt->get_result()->fetch_assoc(); $stmt->close();
                                if ($ticket) {
                                    echo '<h1 class="text-3xl font-bold mb-2">Ticket #'.$ticket['id'].' - '.htmlspecialchars($ticket['subject']).'</h1><div class="text-gray-400 mb-8">Status: <span class="px-2 py-1 text-xs font-bold rounded-full text-white '.get_status_color_class($ticket['status']).'">'.htmlspecialchars($ticket['status']).'</span></div><div class="space-y-6">';
                                    $replies_res = $conn->query("SELECT r.*, u.full_name, u.role FROM ticket_replies r JOIN users u ON r.user_id = u.id WHERE r.ticket_id = $id ORDER BY r.created_at ASC");
                                    while($reply = $replies_res->fetch_assoc()) {
                                        $is_admin = $reply['is_admin_reply'] || $reply['role'] === 'admin';
                                        echo '<div class="'.($is_admin ? 'bg-sky-900/20' : 'bg-[#161b22]/80').' border '.($is_admin ? 'border-sky-700' : 'border-gray-700').' rounded-xl p-6"><div class="flex justify-between items-center mb-4 pb-4 border-b border-gray-700"><p class="font-bold text-lg '.($is_admin ? 'text-sky-300' : 'text-white').'">'.htmlspecialchars($reply['full_name']).'</p><p class="text-sm text-gray-400">'.htmlspecialchars($reply['created_at']).'</p></div><div class="prose prose-invert max-w-none text-gray-300">'.nl2br(htmlspecialchars($reply['message'])).'</div></div>';
                                    } echo '</div>';
                                    if ($ticket['status'] !== 'Closed') {
                                        echo '<div class="mt-12 bg-[#161b22]/80 border border-gray-700 rounded-xl p-8"><h3 class="text-2xl font-bold mb-4">Post a Reply</h3><form method="POST"><input type="hidden" name="post_reply" value="1"><input type="hidden" name="ticket_id" value="'.$id.'"><textarea name="message" rows="8" class="w-full bg-[#0d1117] border border-gray-600 rounded-md p-3" required></textarea><div class="mt-6 text-right"><button type="submit" class="bg-sky-600 font-bold py-2 px-6 rounded-lg hover:bg-sky-700">Submit Reply</button></div></form></div>';
                                    }
                                } else { echo '<p>Ticket not found.</p>'; }
                                break;
                            case 'announcements':
                                echo '<h1 class="text-3xl font-bold mb-8">Announcements</h1><div class="space-y-8">';
                                $ann_res = $conn->query("SELECT * FROM announcements ORDER BY is_pinned DESC, created_at DESC");
                                if ($ann_res->num_rows > 0) {
                                    while($ann = $ann_res->fetch_assoc()) {
                                        echo '<div class="bg-[#161b22]/80 p-6 rounded-xl border border-gray-700"><div class="flex justify-between items-center"><h2 class="text-2xl font-bold text-sky-400">'.htmlspecialchars($ann['title']).'</h2><span class="text-sm text-gray-400">'.date('F j, Y', strtotime($ann['created_at'])).'</span></div><div class="text-gray-300 mt-4 prose prose-invert max-w-none">'.nl2br(htmlspecialchars($ann['content'])).'</div></div>';
                                    }
                                } else {
                                    echo '<p class="text-center text-gray-400">There are no announcements at this time.</p>';
                                }
                                echo '</div>'; break;
                            case 'profile':
                                $stmt = $conn->prepare("SELECT * FROM users WHERE id = ?"); $stmt->bind_param("i", $user_id); $stmt->execute(); $user = $stmt->get_result()->fetch_assoc(); $stmt->close();
                                echo '<h1 class="text-3xl font-bold mb-8">My Details</h1><div class="max-w-xl mx-auto bg-[#161b22]/80 p-8 rounded-xl border border-gray-700"><form method="POST"><input type="hidden" name="update_profile" value="1"><div class="space-y-6"><div><label for="full_name" class="block text-sm font-medium">Full Name</label><input type="text" name="full_name" value="'.htmlspecialchars($user['full_name']).'" class="mt-1 block w-full bg-[#0d1117] border border-gray-600 rounded-md py-2 px-3" required></div><div><label for="company_name" class="block text-sm font-medium">Company Name</label><input type="text" name="company_name" value="'.htmlspecialchars($user['company_name']).'" class="mt-1 block w-full bg-[#0d1117] border border-gray-600 rounded-md py-2 px-3"></div><div><label for="email" class="block text-sm font-medium">Email Address</label><input type="email" name="email" value="'.htmlspecialchars($user['email']).'" class="mt-1 block w-full bg-[#0d1117] border border-gray-600 rounded-md py-2 px-3" required></div><div><label for="address" class="block text-sm font-medium">Address</label><textarea name="address" rows="3" class="mt-1 block w-full bg-[#0d1117] border border-gray-600 rounded-md p-3">'.htmlspecialchars($user['address']).'</textarea></div><div class="border-t border-gray-700 pt-6"><label for="password" class="block text-sm font-medium">New Password (leave blank to keep current)</label><input type="password" name="password" id="password" class="mt-1 block w-full bg-[#0d1117] border border-gray-600 rounded-md py-2 px-3"></div></div><div class="mt-6 text-right"><button type="submit" class="bg-sky-600 font-bold py-2 px-6 rounded-lg hover:bg-sky-700">Save Changes</button></div></form></div>';
                                break;
                            default:
                                $services_count_res = $conn->query("SELECT COUNT(*) as c FROM client_services WHERE user_id = $user_id AND status = 'Active'"); $services_count = $services_count_res ? $services_count_res->fetch_assoc()['c'] : 0;
                                $unpaid_invoices_res = $conn->query("SELECT COUNT(*) as c FROM invoices WHERE user_id = $user_id AND status = 'Unpaid'"); $unpaid_invoices_count = $unpaid_invoices_res ? $unpaid_invoices_res->fetch_assoc()['c'] : 0;
                                $open_tickets_res = $conn->query("SELECT COUNT(*) as c FROM tickets WHERE user_id = $user_id AND status != 'Closed'"); $open_tickets_count = $open_tickets_res ? $open_tickets_res->fetch_assoc()['c'] : 0;
                                echo '<h1 class="text-3xl font-bold">Welcome back, '.htmlspecialchars($_SESSION['full_name']).'</h1><p class="text-gray-400">Here\'s a quick overview of your account.</p><div class="mt-8 grid md:grid-cols-2 lg:grid-cols-3 gap-8"><a href="index.php?page=services" class="bg-[#161b22]/80 p-6 rounded-xl border border-gray-700 hover:border-sky-500 transition-all"><p class="text-5xl font-black text-sky-400">'.$services_count.'</p><p class="mt-2 text-lg font-semibold">Active Services</p></a><a href="index.php?page=invoices" class="bg-[#161b22]/80 p-6 rounded-xl border border-gray-700 hover:border-sky-500 transition-all"><p class="text-5xl font-black text-yellow-400">'.$unpaid_invoices_count.'</p><p class="mt-2 text-lg font-semibold">Unpaid Invoices</p></a><a href="index.php?page=tickets" class="bg-[#161b22]/80 p-6 rounded-xl border border-gray-700 hover:border-sky-500 transition-all"><p class="text-5xl font-black text-yellow-400">'.$open_tickets_count.'</p><p class="mt-2 text-lg font-semibold">Open Tickets</p></a></div>';
                                break;
                        }
                    ?>
                </div>
            </div>
        <?php endif; ?>
    </main>
</body>
</html>
