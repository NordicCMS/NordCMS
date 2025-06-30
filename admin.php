<?php
// --- SETUP & SECURITY ---
// --- Created by NCMS ---
// error_reporting(E_ALL); ini_set('display_errors', 1); // UNCOMMENT FOR DEBUGGING
error_reporting(0); // COMMENT OUT FOR DEBUGGING
session_start();

if (!file_exists('config.php')) {
    header('Location: install.php');
    exit;
}
require_once 'config.php';

// --- AUTHORIZATION: Ensure only logged-in admins can access this page ---
if (!isset($_SESSION['user_id']) || !isset($_SESSION['role']) || $_SESSION['role'] !== 'admin') {
    http_response_code(403);
    die('<!DOCTYPE html><html><head><title>Access Denied</title><script src="https://cdn.tailwindcss.com"></script></head><body class="bg-gray-900 text-white flex items-center justify-center h-screen"><div class="text-center"><h1 class="text-4xl font-bold text-red-500">Access Denied</h1><p class="mt-4">You must be an administrator to view this page.</p><a href="index.php" class="mt-6 inline-block bg-sky-500 px-6 py-2 rounded">Go to Login</a></div></body></html>');
}

// --- DATABASE CONNECTION ---
$conn = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME);
if ($conn->connect_error) {
    die("Database Connection Failed. Please check your config.php file. Error: " . $conn->connect_error);
}

// --- FORM HANDLING (CONTROLLER) ---
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (isset($_POST['update_user'])) {
        $user_id = intval($_POST['user_id']);
        $full_name = trim($_POST['full_name']);
        $email = trim($_POST['email']);
        $company_name = trim($_POST['company_name']);
        $address = trim($_POST['address']);
        $password = $_POST['password'];

        if (!empty($password)) {
            $hashed_password = password_hash($password, PASSWORD_DEFAULT);
            $stmt = $conn->prepare("UPDATE users SET full_name = ?, email = ?, company_name = ?, address = ?, password = ? WHERE id = ?");
            if ($stmt) {
                $stmt->bind_param("sssssi", $full_name, $email, $company_name, $address, $hashed_password, $user_id);
            }
        } else {
            $stmt = $conn->prepare("UPDATE users SET full_name = ?, email = ?, company_name = ?, address = ? WHERE id = ?");
            if ($stmt) {
                $stmt->bind_param("ssssi", $full_name, $email, $company_name, $address, $user_id);
            }
        }
        
        if($stmt && $stmt->execute()){ $_SESSION['success_message'] = "Client #{$user_id} updated successfully."; } else { $_SESSION['error_message'] = "Failed to update client. " . $conn->error; }
        if($stmt) $stmt->close(); 
        header('Location: admin.php?page=users'); exit;
    }
    if (isset($_POST['add_product'])) {
        $name = trim($_POST['name']); $desc = trim($_POST['description']); $price = trim($_POST['price']); $cycle = trim($_POST['billing_cycle']);
        $stmt = $conn->prepare("INSERT INTO products (name, description, price, billing_cycle) VALUES (?, ?, ?, ?)");
        $stmt->bind_param("ssds", $name, $desc, $price, $cycle);
        if($stmt->execute()){ $_SESSION['success_message'] = "Product added successfully."; } else { $_SESSION['error_message'] = "Failed to add product."; }
        $stmt->close(); header('Location: admin.php?page=products'); exit;
    }
    if (isset($_POST['edit_product'])) {
        $id = intval($_POST['product_id']); $name = trim($_POST['name']); $desc = trim($_POST['description']); $price = trim($_POST['price']); $cycle = trim($_POST['billing_cycle']);
        $stmt = $conn->prepare("UPDATE products SET name=?, description=?, price=?, billing_cycle=? WHERE id=?");
        $stmt->bind_param("ssdsi", $name, $desc, $price, $cycle, $id);
        if($stmt->execute()){ $_SESSION['success_message'] = "Product #{$id} updated successfully."; } else { $_SESSION['error_message'] = "Failed to update product."; }
        $stmt->close(); header('Location: admin.php?page=products'); exit;
    }
    if(isset($_POST['admin_reply'])) {
        $ticket_id = intval($_POST['ticket_id']); $message = trim($_POST['message']); $new_status = $_POST['status'];
        $stmt = $conn->prepare("INSERT INTO ticket_replies (ticket_id, user_id, message, is_admin_reply) VALUES (?, ?, ?, 1)");
        $stmt->bind_param("iis", $ticket_id, $_SESSION['user_id'], $message);
        $stmt->execute();
        $stmt->close();
        $stmt_update = $conn->prepare("UPDATE tickets SET status=?, last_reply=NOW() WHERE id = ?");
        $stmt_update->bind_param("si", $new_status, $ticket_id);
        $stmt_update->execute();
        $stmt_update->close();
        $_SESSION['success_message'] = "Your reply has been posted and the ticket status updated.";
        header('Location: admin.php?page=view_ticket&id='.$ticket_id); exit;
    }
    if(isset($_POST['update_order_status'])) {
        $service_id = intval($_POST['service_id']); $new_status = $_POST['new_status'];
        $allowed = ['Active', 'Suspended', 'Terminated', 'Pending'];
        if(in_array($new_status, $allowed)) {
            $stmt = $conn->prepare("UPDATE client_services SET status = ? WHERE id = ?");
            $stmt->bind_param("si", $new_status, $service_id);
            $stmt->execute();
            $_SESSION['success_message'] = "Order #{$service_id} status updated to {$new_status}.";
        }
        header('Location: admin.php?page=orders'); exit;
    }
    if(isset($_POST['delete_order'])) {
        $service_id = intval($_POST['service_id']);
        $conn->query("UPDATE invoices SET client_service_id = NULL WHERE client_service_id = $service_id");
        $stmt = $conn->prepare("DELETE FROM client_services WHERE id = ?");
        $stmt->bind_param("i", $service_id);
        $stmt->execute();
        $_SESSION['success_message'] = "Order #{$service_id} has been deleted.";
        header('Location: admin.php?page=orders'); exit;
    }
    if(isset($_POST['update_invoice_status'])) {
        $invoice_id = intval($_POST['invoice_id']); $new_status = $_POST['new_status'];
        $allowed = ['Paid', 'Unpaid', 'Refunded', 'Cancelled'];
        if(in_array($new_status, $allowed)) {
            $stmt = $conn->prepare("UPDATE invoices SET status = ? WHERE id = ?");
            $stmt->bind_param("si", $new_status, $invoice_id);
            $stmt->execute();
            $_SESSION['success_message'] = "Invoice #{$invoice_id} status updated to {$new_status}.";
        }
        header('Location: admin.php?page=invoices'); exit;
    }
    if (isset($_POST['save_settings'])) {
        $settings_to_save = ['company_name', 'company_address', 'logo_url', 'primary_color', 'paypal_email', 'stripe_pk', 'stripe_sk', 'crypto_address', 'maintenance_mode', 'maintenance_message'];
        $stmt = $conn->prepare("INSERT INTO settings (setting_key, setting_value) VALUES (?, ?) ON DUPLICATE KEY UPDATE setting_value = VALUES(setting_value)");
        foreach($settings_to_save as $key) {
            $value = isset($_POST[$key]) ? trim($_POST[$key]) : '';
            if($key === 'maintenance_mode') { $value = isset($_POST['maintenance_mode']) ? 'on' : 'off'; }
            $stmt->bind_param("ss", $key, $value);
            $stmt->execute();
        }
        $stmt->close();
        $_SESSION['success_message'] = "Settings saved successfully.";
        header('Location: ' . $_SERVER['REQUEST_URI']); exit;
    }
     if (isset($_POST['add_announcement'])) {
        $title = trim($_POST['title']); $content = trim($_POST['content']);
        $is_pinned = isset($_POST['is_pinned']) ? 1 : 0;
        $stmt = $conn->prepare("INSERT INTO announcements (title, content, is_pinned) VALUES (?, ?, ?)");
        $stmt->bind_param("ssi", $title, $content, $is_pinned);
        if($stmt->execute()){ $_SESSION['success_message'] = "Announcement created."; } else { $_SESSION['error_message'] = "Failed to create announcement."; }
        $stmt->close(); header('Location: admin.php?page=announcements'); exit;
    }
    if (isset($_POST['delete_announcement'])) {
        $id = intval($_POST['announcement_id']);
        $stmt = $conn->prepare("DELETE FROM announcements WHERE id = ?");
        $stmt->bind_param("i", $id);
        if($stmt->execute()){ $_SESSION['success_message'] = "Announcement deleted."; } else { $_SESSION['error_message'] = "Failed to delete announcement."; }
        $stmt->close(); header('Location: admin.php?page=announcements'); exit;
    }
    if(isset($_POST['add_subnet'])) {
        $subnet = trim($_POST['subnet']);
        if(!empty($subnet)){
            $stmt = $conn->prepare("INSERT INTO ip_subnets (subnet) VALUES (?)");
            $stmt->bind_param("s", $subnet);
            if($stmt->execute()) { $_SESSION['success_message'] = "Subnet added successfully."; } else { $_SESSION['error_message'] = "Failed to add subnet."; }
            $stmt->close();
        } else {
            $_SESSION['error_message'] = "Subnet field cannot be empty.";
        }
        header('Location: admin.php?page=ip_management'); exit;
    }
    if(isset($_POST['delete_subnet'])) {
        $id = intval($_POST['subnet_id']);
        $stmt = $conn->prepare("DELETE FROM ip_subnets WHERE id = ?");
        $stmt->bind_param("i", $id);
        if($stmt->execute()){ $_SESSION['success_message'] = "Subnet deleted."; } else { $_SESSION['error_message'] = "Failed to delete subnet."; }
        $stmt->close(); header('Location: admin.php?page=ip_management'); exit;
    }
}

// --- GLOBAL VARIABLES for rendering ---
$page = $_GET['page'] ?? 'dashboard';
$error = $_SESSION['error_message'] ?? '';
$success = $_SESSION['success_message'] ?? '';
unset($_SESSION['error_message'], $_SESSION['success_message']);

// --- HELPER FUNCTIONS ---
function get_status_color_class($status) { $map = ['active' => 'bg-green-500', 'paid' => 'bg-green-500', 'answered' => 'bg-sky-500', 'open' => 'bg-yellow-500', 'pending' => 'bg-yellow-500', 'unpaid' => 'bg-yellow-500', 'suspended' => 'bg-red-500', 'terminated' => 'bg-red-700', 'cancelled' => 'bg-gray-500', 'closed' => 'bg-gray-600', 'refunded' => 'bg-purple-500']; return $map[strtolower($status)] ?? 'bg-gray-500'; }
function is_active_nav($current_page, $nav_item) { if (strpos($current_page, $nav_item) === 0 || ($current_page === 'dashboard' && $nav_item === 'dashboard')) { return 'text-sky-400 border-b-2 border-sky-400'; } return 'text-gray-400 hover:text-white'; }
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>Admin Panel - Nordic CMS</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style> body { background-color: #0d1117; font-family: 'Inter', sans-serif; } .aurora-bg { background: radial-gradient(ellipse at top, transparent 40%, #0d1117), linear-gradient(135deg, #0d1117 0%, #0c2a3a 30%, #093642 70%, #0d1117 100%); animation: aurora 15s ease infinite; } @keyframes aurora { 0% { background-position: 0% 50%; } 50% { background-position: 100% 50%; } 100% { background-position: 0% 50%; } } </style>
</head>
<body class="text-white aurora-bg min-h-screen">
    <header class="bg-[#161b22]/50 backdrop-blur-sm sticky top-0 z-50">
        <div class="container mx-auto px-4 sm:px-6 lg:px-8">
            <div class="flex items-center justify-between h-24">
                <a href="admin.php" class="flex items-center space-x-2"><span class="text-2xl font-black text-white">Nord</span><span class="text-2xl font-black text-sky-400">CMS</span><span class="text-xl font-semibold text-gray-400 pl-2">Admin CRM</span></a>
                <div class="flex items-center gap-4">
                    <a href="index.php" class="text-gray-300 hover:text-sky-400 transition-colors">Client View</a>
                    <div class="relative" id="setup-menu-container">
                        <button id="setup-menu-button" class="text-white font-bold py-2 px-5 rounded-lg border-2 border-gray-700 hover:border-sky-400 transition-all">Setup</button>
                        <div id="setup-menu-content" class="hidden absolute right-0 mt-2 w-72 bg-[#161b22] border border-gray-700 rounded-lg shadow-lg p-4 z-50">
                            <div class="space-y-2">
                                <h3 class="font-bold text-sky-400 mb-2 px-2">System Configuration</h3>
                                <a href="admin.php?page=settings" class="block py-2 px-2 hover:bg-sky-500/10 rounded-md">General Settings</a>
                                <a href="admin.php?page=paymentgateways" class="block py-2 px-2 hover:bg-sky-500/10 rounded-md">Payment Gateways</a>
                                <a href="admin.php?page=servers" class="block py-2 px-2 hover:bg-sky-500/10 rounded-md">Servers</a>
                                <a href="admin.php?page=ip_management" class="block py-2 px-2 hover:bg-sky-500/10 rounded-md">IP Management</a>
                                <h3 class="font-bold text-sky-400 mb-2 mt-4 px-2">Products & Services</h3>
                                <a href="admin.php?page=products" class="block py-2 px-2 hover:bg-sky-500/10 rounded-md">Products/Services</a>
                                <a href="admin.php?page=announcements" class="block py-2 px-2 hover:bg-sky-500/10 rounded-md">Announcements</a>
                            </div>
                        </div>
                    </div>
                    <a href="logout.php" class="text-white font-bold py-2 px-5 rounded-lg border-2 border-red-800 hover:border-red-500 transition-all">Logout</a>
                </div>
            </div>
            <div class="flex flex-wrap gap-x-4 border-b border-gray-700">
                <a href="admin.php?page=dashboard" class="py-3 px-4 font-semibold <?php echo is_active_nav($page, 'dashboard'); ?>">Dashboard</a>
                <a href="admin.php?page=users" class="py-3 px-4 font-semibold <?php echo is_active_nav($page, 'user'); ?>">Clients</a>
                <a href="admin.php?page=orders" class="py-3 px-4 font-semibold <?php echo is_active_nav($page, 'orders'); ?>">Orders</a>
                <a href="admin.php?page=invoices" class="py-3 px-4 font-semibold <?php echo is_active_nav($page, 'invoice'); ?>">Invoices</a>
                <a href="admin.php?page=tickets" class="py-3 px-4 font-semibold <?php echo is_active_nav($page, 'ticket'); ?>">Support</a>
            </div>
        </div>
    </header>
    <main class="container mx-auto px-4 sm:px-6 lg:px-8 py-12">
        <?php if (!empty($error)): ?><div class="mb-6 p-4 bg-red-900/50 border border-red-500 text-red-300 rounded-lg"><?php echo htmlspecialchars($error); ?></div><?php endif; ?>
        <?php if (!empty($success)): ?><div class="mb-6 p-4 bg-green-900/50 border border-green-500 text-green-300 rounded-lg"><?php echo htmlspecialchars($success); ?></div><?php endif; ?>
        
        <?php 
        // --- ADMIN PAGE RENDERER ---
        switch($page) {
            case 'users':
                echo '<h1 class="text-3xl font-bold mb-8">All Clients</h1><div class="bg-[#161b22]/80 border border-gray-700 rounded-xl shadow-lg overflow-x-auto"><table class="w-full text-left"><thead class="bg-[#0d1117]/50"><tr><th class="p-4">ID</th><th class="p-4">Email</th><th class="p-4">Full Name</th><th class="p-4">Role</th><th class="p-4">Registered</th><th class="p-4"></th></tr></thead><tbody class="divide-y divide-gray-800">';
                $result = $conn->query("SELECT id, email, full_name, role, created_at FROM users ORDER BY created_at DESC");
                while($row = $result->fetch_assoc()) echo "<tr><td class='p-4'>#".$row['id']."</td><td class='p-4'>".htmlspecialchars($row['email'])."</td><td class='p-4'>".htmlspecialchars($row['full_name'])."</td><td class='p-4'>".htmlspecialchars($row['role'])."</td><td class='p-4'>".htmlspecialchars($row['created_at'])."</td><td class='p-4 text-right'><a href='admin.php?page=edit_user&id=".$row['id']."' class='font-semibold text-sky-400 hover:text-sky-300'>Edit</a></td></tr>";
                echo '</tbody></table></div>';
                break;
            
            case 'edit_user':
                 $id = intval($_GET['id']); $user_res = $conn->query("SELECT * FROM users WHERE id = $id"); $user = $user_res->fetch_assoc();
                 if($user) { echo '<h1 class="text-3xl font-bold mb-8">Edit Client: '.htmlspecialchars($user['full_name']).'</h1><div class="max-w-xl mx-auto bg-[#161b22]/80 p-8 rounded-xl border border-gray-700"><form method="POST" class="space-y-4"><input type="hidden" name="update_user" value="1"><input type="hidden" name="user_id" value="'.$user['id'].'"><div><label class="block text-sm">Full Name</label><input type="text" name="full_name" value="'.htmlspecialchars($user['full_name']).'" class="mt-1 block w-full bg-[#0d1117] border border-gray-600 rounded-md py-2 px-3" required></div><div><label class="block text-sm">Email Address</label><input type="email" name="email" value="'.htmlspecialchars($user['email']).'" class="mt-1 block w-full bg-[#0d1117] border border-gray-600 rounded-md py-2 px-3" required></div><div><label class="block text-sm">Company Name</label><input type="text" name="company_name" value="'.htmlspecialchars($user['company_name']).'" class="mt-1 block w-full bg-[#0d1117] border border-gray-600 rounded-md py-2 px-3"></div><div><label class="block text-sm">Address</label><textarea name="address" rows="3" class="mt-1 block w-full bg-[#0d1117] border border-gray-600 rounded-md p-3">'.htmlspecialchars($user['address']).'</textarea></div><div><label class="block text-sm">New Password (leave blank to keep current)</label><input type="password" name="password" class="mt-1 block w-full bg-[#0d1117] border border-gray-600 rounded-md py-2 px-3"></div><div class="flex gap-4"><a href="admin.php?page=users" class="w-1/2 text-center bg-gray-700 font-bold py-2 px-4 rounded-lg hover:bg-gray-600">Cancel</a><button type="submit" class="w-1/2 bg-sky-600 font-bold py-2 px-4 rounded-lg hover:bg-sky-700">Save Changes</button></div></form></div>'; } else { echo "<p>User not found.</p>"; }
                break;
            
            case 'orders':
                echo '<h1 class="text-3xl font-bold mb-8">All Client Orders / Services</h1><div class="bg-[#161b22]/80 border border-gray-700 rounded-xl shadow-lg overflow-x-auto"><table class="w-full text-left"><thead class="bg-[#0d1117]/50"><tr><th class="p-4">Order ID</th><th class="p-4">Client</th><th class="p-4">Product</th><th class="p-4">Status</th><th class="p-4 w-64">Actions</th></tr></thead><tbody class="divide-y divide-gray-800">';
                $result = $conn->query("SELECT cs.id, u.email, p.name as product_name, cs.status FROM client_services cs JOIN users u ON cs.user_id = u.id JOIN products p ON cs.product_id = p.id ORDER BY cs.created_at DESC");
                while($row = $result->fetch_assoc()) {
                    echo "<tr class='align-middle'><td class='p-4'>#".$row['id']."</td><td class='p-4'>".htmlspecialchars($row['email'])."</td><td class='p-4 font-bold'>".htmlspecialchars($row['product_name'])."</td><td class='p-4'><span class='px-2 py-1 text-xs font-bold rounded-full text-white ".get_status_color_class($row['status'])."'>".htmlspecialchars($row['status'])."</span></td><td class='p-4 flex gap-2'>";
                    echo "<form method='POST' onsubmit='return confirm(\"Activate this order?\");'><input type='hidden' name='service_id' value='".$row['id']."'><input type='hidden' name='new_status' value='Active'><button type='submit' name='update_order_status' class='text-xs bg-green-600 hover:bg-green-500 p-2 rounded'>Activate</button></form>";
                    echo "<form method='POST' onsubmit='return confirm(\"Suspend this order?\");'><input type='hidden' name='service_id' value='".$row['id']."'><input type='hidden' name='new_status' value='Suspended'><button type='submit' name='update_order_status' class='text-xs bg-yellow-600 hover:bg-yellow-500 p-2 rounded'>Suspend</button></form>";
                    echo "<form method='POST' onsubmit='return confirm(\"Terminate this order?\");'><input type='hidden' name='service_id' value='".$row['id']."'><input type='hidden' name='new_status' value='Terminated'><button type='submit' name='update_order_status' class='text-xs bg-red-600 hover:bg-red-500 p-2 rounded'>Terminate</button></form>";
                    echo "<form method='POST' onsubmit='return confirm(\"DELETE this order forever? This cannot be undone.\");'><input type='hidden' name='service_id' value='".$row['id']."'><button type='submit' name='delete_order' class='text-xs bg-gray-700 hover:bg-gray-600 p-2 rounded'>Delete</button></form>";
                    echo "</td></tr>";
                }
                echo '</tbody></table></div>';
                break;
            
            case 'products':
                echo '<div class="flex justify-between items-center mb-8"><h1 class="text-3xl font-bold">Product Management</h1></div>';
                echo '<div class="grid lg:grid-cols-3 gap-8 items-start"><div class="lg:col-span-2 bg-[#161b22]/80 border border-gray-700 rounded-xl shadow-lg overflow-x-auto"><table class="w-full text-left"><thead class="bg-[#0d1117]/50"><tr><th class="p-4">ID</th><th class="p-4">Name</th><th class="p-4">Price</th><th class="p-4">Cycle</th><th class="p-4"></th></tr></thead><tbody class="divide-y divide-gray-800">';
                $result = $conn->query("SELECT * FROM products ORDER BY id ASC");
                while($row = $result->fetch_assoc()) echo "<tr><td class='p-4'>#".$row['id']."</td><td class='p-4 font-bold'>".htmlspecialchars($row['name'])."</td><td class='p-4'>€".htmlspecialchars($row['price'])."</td><td class='p-4'>".htmlspecialchars($row['billing_cycle'])."</td><td class='p-4 text-right'><a href='admin.php?page=edit_product&id=".$row['id']."' class='font-semibold text-sky-400 hover:text-sky-300'>Edit</a></td></tr>";
                echo '</tbody></table></div><div class="bg-[#161b22]/80 p-8 rounded-xl border border-gray-700"><h3 class="text-xl font-bold mb-4">Add New Product</h3><form method="POST" class="space-y-4"><input type="hidden" name="add_product" value="1"><div><label for="name" class="block text-sm">Name</label><input type="text" name="name" class="mt-1 block w-full bg-[#0d1117] border border-gray-600 rounded-md py-2 px-3" required></div><div><label for="description" class="block text-sm">Description</label><textarea name="description" rows="3" class="mt-1 block w-full bg-[#0d1117] border border-gray-600 rounded-md py-2 px-3"></textarea></div><div><label for="price" class="block text-sm">Price (€)</label><input type="number" step="0.01" name="price" class="mt-1 block w-full bg-[#0d1117] border border-gray-600 rounded-md py-2 px-3" required></div><div><label for="billing_cycle" class="block text-sm">Billing Cycle</label><select name="billing_cycle" class="mt-1 block w-full bg-[#0d1117] border border-gray-600 rounded-md py-2 px-3"><option>Monthly</option><option>Quarterly</option><option>Annually</option></select></div><button type="submit" class="w-full bg-sky-600 font-bold py-2 px-4 rounded-lg hover:bg-sky-700">Add Product</button></form></div></div>';
                break;

            case 'edit_product':
                $id = intval($_GET['id']); $product_res = $conn->query("SELECT * FROM products WHERE id = $id");
                $product = $product_res->fetch_assoc();
                if($product) { echo '<h1 class="text-3xl font-bold mb-8">Edit Product: '.htmlspecialchars($product['name']).'</h1><div class="max-w-xl mx-auto bg-[#161b22]/80 p-8 rounded-xl border border-gray-700"><form method="POST" class="space-y-4"><input type="hidden" name="edit_product" value="1"><input type="hidden" name="product_id" value="'.$product['id'].'"><div><label for="name" class="block text-sm">Name</label><input type="text" name="name" value="'.htmlspecialchars($product['name']).'" class="mt-1 block w-full bg-[#0d1117] border border-gray-600 rounded-md py-2 px-3" required></div><div><label for="description" class="block text-sm">Description</label><textarea name="description" rows="3" class="mt-1 block w-full bg-[#0d1117] border border-gray-600 rounded-md py-2 px-3">'.htmlspecialchars($product['description']).'</textarea></div><div><label for="price" class="block text-sm">Price (€)</label><input type="number" step="0.01" name="price" value="'.htmlspecialchars($product['price']).'" class="mt-1 block w-full bg-[#0d1117] border border-gray-600 rounded-md py-2 px-3" required></div><div><label for="billing_cycle" class="block text-sm">Billing Cycle</label><select name="billing_cycle" class="mt-1 block w-full bg-[#0d1117] border border-gray-600 rounded-md py-2 px-3"><option '.($product['billing_cycle'] == 'Monthly' ? 'selected' : '').'>Monthly</option><option '.($product['billing_cycle'] == 'Quarterly' ? 'selected' : '').'>Quarterly</option><option '.($product['billing_cycle'] == 'Annually' ? 'selected' : '').'>Annually</option></select></div><div class="flex gap-4"><a href="admin.php?page=products" class="w-1/2 text-center bg-gray-700 font-bold py-2 px-4 rounded-lg hover:bg-gray-600">Cancel</a><button type="submit" class="w-1/2 bg-sky-600 font-bold py-2 px-4 rounded-lg hover:bg-sky-700">Save Changes</button></div></form></div>'; } else { echo "<p>Product not found.</p>"; }
                break;
            
            case 'tickets':
                echo '<h1 class="text-3xl font-bold mb-8">All Support Tickets</h1><div class="bg-[#161b22]/80 border border-gray-700 rounded-xl shadow-lg overflow-x-auto"><table class="w-full text-left"><thead class="bg-[#0d1117]/50"><tr><th class="p-4">ID</th><th class="p-4">Subject</th><th class="p-4">Client</th><th class="p-4">Status</th><th class="p-4">Last Updated</th><th class="p-4"></th></tr></thead><tbody class="divide-y divide-gray-800">';
                $tickets_res = $conn->query("SELECT t.id, t.subject, t.status, t.last_reply, u.email FROM tickets t JOIN users u ON t.user_id = u.id ORDER BY t.last_reply DESC");
                if ($tickets_res->num_rows > 0) { while($row = $tickets_res->fetch_assoc()) echo "<tr><td class='p-4'>#".$row['id']."</td><td class='p-4 font-bold'>".htmlspecialchars($row['subject'])."</td><td class='p-4'>".htmlspecialchars($row['email'])."</td><td class='p-4'><span class='px-2 py-1 text-xs font-bold rounded-full text-white ".get_status_color_class($row['status'])."'>".htmlspecialchars($row['status'])."</span></td><td class='p-4'>".htmlspecialchars($row['last_reply'])."</td><td class='p-4 text-right'><a href='admin.php?page=view_ticket&id=".$row['id']."' class='font-semibold text-sky-400 hover:text-sky-300'>View</a></td></tr>"; } else { echo "<tr><td colspan='6' class='p-4 text-center text-gray-400'>No tickets found.</td></tr>"; }
                echo '</tbody></table></div>'; break;
            
            case 'view_ticket':
                $id = intval($_GET['id']); $ticket_res = $conn->query("SELECT t.*, u.full_name, u.email FROM tickets t JOIN users u ON t.user_id = u.id WHERE t.id = $id");
                $ticket = $ticket_res->fetch_assoc();
                if ($ticket) {
                    echo '<h1 class="text-3xl font-bold mb-2">Ticket #'.$ticket['id'].' - '.htmlspecialchars($ticket['subject']).'</h1><div class="text-gray-400 mb-8">Opened by '.htmlspecialchars($ticket['full_name']).'</div><div class="space-y-6">';
                    $replies_res = $conn->query("SELECT r.*, u.full_name, u.role FROM ticket_replies r JOIN users u ON r.user_id = u.id WHERE r.ticket_id = $id ORDER BY r.created_at ASC");
                    while($reply = $replies_res->fetch_assoc()) {
                        $is_admin = $reply['is_admin_reply'] || $reply['role'] === 'admin';
                        echo '<div class="'.($is_admin ? 'bg-sky-900/20' : 'bg-[#161b22]/80').' border '.($is_admin ? 'border-sky-700' : 'border-gray-700').' rounded-xl p-6"><div class="flex justify-between items-center mb-4 pb-4 border-b border-gray-700"><p class="font-bold text-lg '.($is_admin ? 'text-sky-300' : 'text-white').'">'.htmlspecialchars($reply['full_name']).'</p><p class="text-sm text-gray-400">'.htmlspecialchars($reply['created_at']).'</p></div><div class="prose prose-invert max-w-none text-gray-300">'.nl2br(htmlspecialchars($reply['message'])).'</div></div>';
                    } echo '</div>';
                    echo '<div class="mt-12 bg-[#161b22]/80 border border-gray-700 rounded-xl p-8"><h3 class="text-2xl font-bold mb-4">Post a Reply</h3><form method="POST"><input type="hidden" name="admin_reply" value="1"><input type="hidden" name="ticket_id" value="'.$id.'"><textarea name="message" rows="8" class="w-full bg-[#0d1117] border border-gray-600 rounded-md p-3" required></textarea><div class="mt-4 flex items-center justify-between"><div class="flex items-center gap-4"><label for="status" class="font-semibold">Set Status:</label><select name="status" class="bg-[#0d1117] border border-gray-600 rounded-md py-2 px-3"><option value="Answered" selected>Answered</option><option value="Closed">Closed</option><option value="Open">Re-Open</option></select></div><button type="submit" class="bg-sky-600 font-bold py-2 px-6 rounded-lg hover:bg-sky-700">Submit Reply</button></div></form></div>';
                } else { echo '<p>Ticket not found.</p>'; }
                break;

            case 'invoices':
                echo '<h1 class="text-3xl font-bold mb-8">All Invoices</h1><div class="bg-[#161b22]/80 border border-gray-700 rounded-xl shadow-lg overflow-x-auto"><table class="w-full text-left"><thead class="bg-[#0d1117]/50"><tr><th class="p-4">Invoice #</th><th class="p-4">Client</th><th class="p-4">Amount</th><th class="p-4">Status</th><th class="p-4 w-64">Actions</th></tr></thead><tbody class="divide-y divide-gray-800">';
                $result = $conn->query("SELECT i.id, i.amount, i.status, u.email FROM invoices i JOIN users u ON i.user_id = u.id ORDER BY i.id DESC");
                while($row = $result->fetch_assoc()) { echo "<tr class='align-middle'><td class='p-4 font-bold'>#".$row['id']."</td><td class='p-4'>".htmlspecialchars($row['email'])."</td><td class='p-4'>€".htmlspecialchars($row['amount'])."</td><td class='p-4'><span class='px-2 py-1 text-xs font-bold rounded-full text-white ".get_status_color_class($row['status'])."'>".htmlspecialchars($row['status'])."</span></td><td class='p-4'><form method='POST' class='flex gap-2 items-center'><input type='hidden' name='invoice_id' value='".$row['id']."'><select name='new_status' class='bg-[#0d1117] border border-gray-600 rounded-md py-1 px-2 text-sm'><option value='Paid' ".($row['status']=='Paid'?'selected':'').">Paid</option><option value='Unpaid' ".($row['status']=='Unpaid'?'selected':'').">Unpaid</option><option value='Refunded' ".($row['status']=='Refunded'?'selected':'').">Refunded</option><option value='Cancelled' ".($row['status']=='Cancelled'?'selected':'').">Cancelled</option></select><button type='submit' name='update_invoice_status' class='bg-sky-700 hover:bg-sky-600 p-2 rounded text-xs'>Save</button></form></td></tr>"; }
                echo '</tbody></table></div>'; break;
            
            case 'settings':
                $settings_res = $conn->query("SELECT * FROM settings"); $settings = []; while($row = $settings_res->fetch_assoc()) { $settings[$row['setting_key']] = $row['setting_value']; }
                echo '<h1 class="text-3xl font-bold mb-8">General Settings</h1><div class="max-w-4xl mx-auto"><form method="POST"><input type="hidden" name="save_settings" value="1">';
                echo '<div class="bg-[#161b22]/80 p-8 rounded-xl border border-gray-700 mb-8"><h2 class="text-2xl font-bold text-sky-400 mb-6">Branding & Company Information</h2><div class="space-y-6">';
                echo '<div><label for="company_name" class="block text-sm">Company Name</label><input type="text" name="company_name" value="'.htmlspecialchars($settings['company_name'] ?? 'NCMS').'" class="mt-1 block w-full bg-[#0d1117] border border-gray-600 rounded-md py-2 px-3"></div>';
                echo '<div><label for="company_address" class="block text-sm">Company Address (for Invoices)</label><textarea name="company_address" rows="3" class="mt-1 block w-full bg-[#0d1117] border border-gray-600 rounded-md p-3">'.htmlspecialchars($settings['company_address'] ?? "Storgata 44\n9008 Tromsø\nNorway").'</textarea></div>';
                echo '<div><label for="logo_url" class="block text-sm">Logo URL</label><input type="text" name="logo_url" value="'.htmlspecialchars($settings['logo_url'] ?? '').'" class="mt-1 block w-full bg-[#0d1117] border border-gray-600 rounded-md py-2 px-3" placeholder="https://yourdomain.com/logo.png"></div>';
                echo '<div><label for="primary_color" class="block text-sm">Primary Brand Color</label><input type="color" name="primary_color" value="'.htmlspecialchars($settings['primary_color'] ?? '#38bdf8').'" class="mt-1 block w-full h-10 bg-[#0d1117] border border-gray-600 rounded-md p-0"></div>';
                echo '</div></div>';
                echo '<div class="bg-[#161b22]/80 p-8 rounded-xl border border-gray-700 mb-8"><h2 class="text-2xl font-bold text-sky-400 mb-6">Maintenance Mode</h2><div class="space-y-6">';
                echo '<div class="flex items-center"><input type="checkbox" id="maintenance_mode" name="maintenance_mode" '.($settings['maintenance_mode'] ?? 'off' == 'on' ? 'checked' : '').' class="h-5 w-5 rounded bg-gray-700 border-gray-600 focus:ring-sky-500 text-sky-500"><label for="maintenance_mode" class="ml-3 text-lg">Enable Maintenance Mode</label></div>';
                echo '<div><label for="maintenance_message" class="block text-sm">Maintenance Message</label><textarea name="maintenance_message" rows="3" class="mt-1 block w-full bg-[#0d1117] border border-gray-600 rounded-md p-3">'.htmlspecialchars($settings['maintenance_message'] ?? 'We are currently performing scheduled maintenance. We should be back online shortly. Thank you for your patience.').'</textarea></div>';
                echo '</div></div>';
                echo '<div class="mt-6"><button type="submit" class="w-full bg-sky-600 font-bold py-3 rounded-lg hover:bg-sky-700">Save All Settings</button></div></form></div>';
                break;

            case 'paymentgateways':
                 $settings_res = $conn->query("SELECT * FROM settings"); $settings = []; while($row = $settings_res->fetch_assoc()) { $settings[$row['setting_key']] = $row['setting_value']; }
                echo '<h1 class="text-3xl font-bold mb-8">Payment Gateways</h1><div class="max-w-2xl mx-auto bg-[#161b22]/80 p-8 rounded-xl border border-gray-700"><form method="POST" action="admin.php?page=settings"><input type="hidden" name="save_settings" value="1"><div class="space-y-6"><h3 class="text-lg font-semibold text-sky-400 border-b border-sky-800 pb-2">PayPal</h3><div><label for="paypal_email" class="block text-sm">PayPal Email</label><input type="email" name="paypal_email" value="'.htmlspecialchars($settings['paypal_email'] ?? '').'" class="mt-1 block w-full bg-[#0d1117] border border-gray-600 rounded-md py-2 px-3"></div><h3 class="text-lg font-semibold text-sky-400 border-b border-sky-800 pb-2 mt-6">Stripe</h3><div><label for="stripe_pk" class="block text-sm">Stripe Publishable Key</label><input type="text" name="stripe_pk" value="'.htmlspecialchars($settings['stripe_pk'] ?? '').'" class="mt-1 block w-full bg-[#0d1117] border border-gray-600 rounded-md py-2 px-3"></div><div><label for="stripe_sk" class="block text-sm">Stripe Secret Key</label><input type="password" name="stripe_sk" placeholder="Unchanged" class="mt-1 block w-full bg-[#0d1117] border border-gray-600 rounded-md py-2 px-3"></div><h3 class="text-lg font-semibold text-sky-400 border-b border-sky-800 pb-2 mt-6">Cryptocurrency</h3><div><label for="crypto_address" class="block text-sm">BTC Address (Example)</label><input type="text" name="crypto_address" value="'.htmlspecialchars($settings['crypto_address'] ?? '').'" class="mt-1 block w-full bg-[#0d1117] border border-gray-600 rounded-md py-2 px-3"></div><div class="pt-6 border-t border-gray-700 mt-6"><button type="submit" class="w-full bg-sky-600 font-bold py-3 rounded-lg hover:bg-sky-700">Save Payment Settings</button></div></div></form></div>';
                break;
            
            case 'ip_management':
                echo '<div class="flex justify-between items-center mb-8"><h1 class="text-3xl font-bold">IP Subnet Management</h1></div><div class="grid lg:grid-cols-3 gap-8 items-start"><div class="lg:col-span-2 bg-[#161b22]/80 border border-gray-700 rounded-xl shadow-lg overflow-x-auto"><table class="w-full text-left"><thead class="bg-[#0d1117]/50"><tr><th class="p-4">ID</th><th class="p-4">Subnet</th><th class="p-4">Assigned To</th><th class="p-4"></th></tr></thead><tbody class="divide-y divide-gray-800">';
                $result = $conn->query("SELECT * FROM ip_subnets ORDER BY id ASC");
                while($row = $result->fetch_assoc()) echo "<tr><td class='p-4'>#".$row['id']."</td><td class='p-4 font-mono'>".htmlspecialchars($row['subnet'])."</td><td class='p-4'>".($row['assigned_to'] ? 'Client #'.$row['assigned_to'] : 'Unassigned')."</td><td class='p-4 text-right'><form method='POST' onsubmit='return confirm(\"Delete this subnet?\")'><input type='hidden' name='delete_subnet' value='1'><input type='hidden' name='subnet_id' value='".$row['id']."'><button type='submit' class='text-red-500 hover:text-red-400 font-semibold'>Delete</button></form></td></tr>";
                echo '</tbody></table></div><div class="bg-[#161b22]/80 p-8 rounded-xl border border-gray-700"><h3 class="text-xl font-bold mb-4">Add Subnet</h3><form method="POST" class="space-y-4"><input type="hidden" name="add_subnet" value="1"><div><label for="subnet" class="block text-sm">Subnet (e.g., 192.168.1.0/24)</label><input type="text" name="subnet" class="mt-1 block w-full bg-[#0d1117] border border-gray-600 rounded-md py-2 px-3" required></div><button type="submit" class="w-full bg-sky-600 font-bold py-2 px-4 rounded-lg hover:bg-sky-700">Add Subnet</button></form></div></div>';
                break;

            case 'announcements':
                echo '<div class="flex justify-between items-center mb-8"><h1 class="text-3xl font-bold">Announcements</h1></div><div class="grid lg:grid-cols-3 gap-8 items-start"><div class="lg:col-span-2 space-y-4">';
                $ann_res = $conn->query("SELECT * FROM announcements ORDER BY created_at DESC");
                while($ann = $ann_res->fetch_assoc()) { echo '<div class="bg-[#161b22]/80 p-4 rounded-xl border border-gray-700 flex justify-between items-center"><div><h3 class="font-bold text-white">'.htmlspecialchars($ann['title']).'</h3><p class="text-sm text-gray-400">'.date('M d, Y', strtotime($ann['created_at'])).'</p></div><form method="POST" onsubmit="return confirm(\'Delete this announcement?\');"><input type="hidden" name="delete_announcement" value="1"><input type="hidden" name="announcement_id" value="'.$ann['id'].'"><button type="submit" class="text-red-500 hover:text-red-400 font-semibold">Delete</button></form></div>'; }
                echo '</div><div class="bg-[#161b22]/80 p-8 rounded-xl border border-gray-700"><h3 class="text-xl font-bold mb-4">Create Announcement</h3><form method="POST" class="space-y-4"><input type="hidden" name="add_announcement" value="1"><div><label for="title" class="block text-sm">Title</label><input type="text" name="title" class="mt-1 block w-full bg-[#0d1117] border border-gray-600 rounded-md py-2 px-3" required></div><div><label for="content" class="block text-sm">Content (HTML allowed)</label><textarea name="content" rows="6" class="mt-1 block w-full bg-[#0d1117] border border-gray-600 rounded-md py-2 px-3"></textarea></div><div><label class="flex items-center"><input type="checkbox" name="is_pinned" value="1" class="h-4 w-4 bg-gray-700 border-gray-600 rounded mr-2"><span class="text-sm">Pin this announcement</span></label></div><button type="submit" class="w-full bg-sky-600 font-bold py-2 px-4 rounded-lg hover:bg-sky-700">Post Announcement</button></form></div></div>';
                break;

            case 'servers':
                echo '<h1 class="text-3xl font-bold mb-8">Server Management (VirtFusion)</h1><div class="bg-[#161b22]/80 border border-gray-700 rounded-xl p-6 text-center text-gray-400"><p>This section is reserved for VirtFusion API integration.</p><p class="mt-2">You would build the functionality here to add/edit VirtFusion nodes and link them to products for automated provisioning.</p></div>'; break;
            
            default: // Dashboard
                $total_clients = $conn->query("SELECT COUNT(*) as c FROM users WHERE role='user'")->fetch_assoc()['c'];
                $active_services = $conn->query("SELECT COUNT(*) as c FROM client_services WHERE status='Active'")->fetch_assoc()['c'];
                $open_tickets = $conn->query("SELECT COUNT(*) as c FROM tickets WHERE status='Open' OR status='Answered'")->fetch_assoc()['c'];
                $rev_month = $conn->query("SELECT SUM(amount) as total FROM invoices WHERE status='Paid' AND MONTH(issue_date) = MONTH(CURDATE()) AND YEAR(issue_date) = YEAR(CURDATE())")->fetch_assoc()['total'] ?? 0;
                $rev_quarter = $conn->query("SELECT SUM(amount) as total FROM invoices WHERE status='Paid' AND QUARTER(issue_date) = QUARTER(CURDATE()) AND YEAR(issue_date) = YEAR(CURDATE())")->fetch_assoc()['total'] ?? 0;
                $rev_year = $conn->query("SELECT SUM(amount) as total FROM invoices WHERE status='Paid' AND YEAR(issue_date) = YEAR(CURDATE())")->fetch_assoc()['total'] ?? 0;
                
                echo '<h1 class="text-3xl font-bold">Admin Dashboard</h1>';
                echo '<div class="mt-8 grid md:grid-cols-3 gap-8"><div class="bg-[#161b22]/80 p-6 rounded-xl border border-gray-700"><p class="text-5xl font-black text-sky-400" data-counter-target="'.$total_clients.'">0</p><p class="mt-2 text-lg font-semibold">Total Clients</p></div><div class="bg-[#161b22]/80 p-6 rounded-xl border border-gray-700"><p class="text-5xl font-black text-sky-400" data-counter-target="'.$active_services.'">0</p><p class="mt-2 text-lg font-semibold">Active Services</p></div><div class="bg-[#161b22]/80 p-6 rounded-xl border border-gray-700"><p class="text-5xl font-black text-yellow-400" data-counter-target="'.$open_tickets.'">0</p><p class="mt-2 text-lg font-semibold">Open Tickets</p></div></div>';
                echo '<h2 class="text-2xl font-bold mt-12 mb-4">Revenue Overview</h2>';
                echo '<div class="grid md:grid-cols-3 gap-8"><div class="bg-[#161b22]/80 p-6 rounded-xl border border-gray-700"><p class="text-4xl font-black text-green-400" data-counter-target="'.$rev_month.'" data-counter-decimals="2">€0.00</p><p class="mt-2 text-lg font-semibold">This Month</p></div><div class="bg-[#161b22]/80 p-6 rounded-xl border border-gray-700"><p class="text-4xl font-black text-green-400" data-counter-target="'.$rev_quarter.'" data-counter-decimals="2">€0.00</p><p class="mt-2 text-lg font-semibold">This Quarter</p></div><div class="bg-[#161b22]/80 p-6 rounded-xl border border-gray-700"><p class="text-4xl font-black text-green-400" data-counter-target="'.$rev_year.'" data-counter-decimals="2">€0.00</p><p class="mt-2 text-lg font-semibold">This Year</p></div></div>';
                break;
        }
        ?>
    </main>
    <script>
        const menuButton = document.getElementById('setup-menu-button');
        const menuContent = document.getElementById('setup-menu-content');
        if(menuButton) {
            menuButton.addEventListener('click', (e) => {
                e.stopPropagation();
                menuContent.classList.toggle('hidden');
            });
            document.addEventListener('click', (e) => {
                if (menuContent && !menuButton.contains(e.target) && !menuContent.contains(e.target)) {
                    menuContent.classList.add('hidden');
                }
            });
        }
        
        const counters = document.querySelectorAll('[data-counter-target]');
        const counterObserver = new IntersectionObserver((entries, obs) => {
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    const el = entry.target;
                    const target = +el.dataset.counterTarget;
                    const duration = 1500;
                    const suffix = el.dataset.counterSuffix || '';
                    const decimals = +el.dataset.counterDecimals || 0;
                    let start = 0;
                    let startTime = null;

                    function animateCounter(timestamp) {
                        if (!startTime) startTime = timestamp;
                        const progress = Math.min((timestamp - startTime) / duration, 1);
                        const current = start + progress * (target - start);
                        
                        let formattedNumber = '';
                        if (decimals > 0) {
                            formattedNumber = '€' + current.toFixed(decimals);
                        } else {
                            formattedNumber = Math.floor(current).toLocaleString();
                        }
                        
                        el.innerText = formattedNumber;

                        if (progress < 1) {
                            requestAnimationFrame(animateCounter);
                        } else {
                            if (decimals > 0) {
                                el.innerText = '€' + target.toFixed(decimals);
                            } else {
                                el.innerText = target.toLocaleString();
                            }
                        }
                    }
                    requestAnimationFrame(animateCounter);
                    obs.unobserve(el);
                }
            });
        }, { threshold: 0.8 });
        counters.forEach(counter => { counterObserver.observe(counter); });
    </script>
</body>
</html>
