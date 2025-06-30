![Image](https://github.com/user-attachments/assets/e6280369-5218-48cd-b757-7b698688a081)

NordicCRM - In-House Hosting Management Panel
NordicVM CRM is a custom-built Client Relationship Manager (CRM) and billing system designed for infrastructure and web hosting providers. It provides a complete, self-hosted solution for managing clients, services, billing, and support, inspired by industry-standard platforms like WHMCS.

This application is built with vanilla PHP and MySQL, using Tailwind CSS for a modern and responsive user interface. It is designed to be easily deployed.

Core Features
Client Area (index.php)
The client panel provides customers with a full suite of self-service tools:

Secure Authentication: Full user registration, login, and a secure token-based password reset system.

Client Dashboard: An at-a-glance overview of active services, unpaid invoices, and open support tickets.

Service Management: Clients can view their active services, including order date and next due date.

Product Ordering: A dedicated page to browse available products and place new orders.

Automated Invoicing: Invoices are automatically generated when a new order is placed.

Invoice Management: Clients can view all past invoices, download them as a PDF for their records, and see available payment options.

Payment Gateway Ready: The invoice page dynamically displays payment buttons (Stripe, PayPal, Crypto) based on which gateways are configured in the admin panel.

Full Support Ticket System: Clients can open new tickets, categorize them by department (e.g., Support, Billing), set a priority, view their ticket history, and reply to ongoing conversations.

Profile Management: A dedicated "My Details" page where clients can update their name, company, address, and password.

Announcements: A page to view all company news and maintenance notices posted by an administrator.

Maintenance Mode: A functional maintenance mode that, when enabled by an admin, will lock the client area and display a custom message.

----
Admin Panel (admin.php)
The powerful, WHMCS-inspired backend gives administrators full control over the business:

Analytics Dashboard: A main dashboard with key metrics, including total clients, active services, open tickets, and animated revenue statistics for the current month, quarter, and year.

Mega Menu Navigation: All management and setup options are organized into a clean, space-saving mega menu for easy access.

Client Management: View a list of all registered clients. Functioning Edit button allows admins to update client details (name, company, address, password). A Delete button allows for complete removal of a client and their associated data.

Order Management: View a list of all client orders. For each order, admins have functional buttons to manually Activate, Suspend, Terminate, or Delete the service.

Full Product Management: Create, view, and edit all product details, including name, description, price, and billing cycle.

Complete Ticket System: View all tickets from all clients, sorted by the last reply. Admins can click to view the full conversation and post replies, which changes the ticket status to "Answered".

Advanced Invoice Management: View all invoices in the system and manually change their status to Paid, Unpaid, Refunded, or Cancelled.

Comprehensive Settings Panel:

General Settings: Manage company name, address, and logo URL for invoice branding.

Maintenance Mode: A working toggle to enable or disable the client-facing maintenance page.

Payment Gateways: A secure page to enter and save API keys for Stripe, a PayPal email address, and a cryptocurrency address.

IP Management: A foundational system to add and manage IP subnets in preparation for automation.

Announcements: A full interface to create, pin, and delete client-facing announcements.

VirtFusion Integration Ready: A dedicated "Servers" page to add and manage VirtFusion nodes, including a functional "Create VM" form that creates the service and invoice in the CRM, ready for the final API call to be added.

--

Tech Stack
Backend: PHP

Database: MySQL

Frontend: HTML, Tailwind CSS

JavaScript: Vanilla JS for menus and animations

Installation
SOON - DEMO AT https://nordicvm.com/client/

Future Development Goals
The foundation of this CRM is complete. The next major step is to implement the server automation logic and more structure.

![Image](https://github.com/user-attachments/assets/c4ddce42-8383-42c6-9d55-9b8bba90e576)
![Image](https://github.com/user-attachments/assets/e2ce1af2-9c51-40da-b491-5871924aa47c)
![Image](https://github.com/user-attachments/assets/58c60915-ab3b-4531-b6b0-f8e428ddab8e)
![Image](https://github.com/user-attachments/assets/266a0976-7be6-4c47-99cb-e66e56ef2f1d)
![Image](https://github.com/user-attachments/assets/b8e8f4b4-d081-48b3-803d-0a642771e323)
![Image](https://github.com/user-attachments/assets/ea85ed6d-eaba-474b-befd-62682b55a9ba)
![Image](https://github.com/user-attachments/assets/684ccdea-8396-444a-ac4b-920b8f3a1e9a)
![Image](https://github.com/user-attachments/assets/df3c23fc-9e1a-43a1-a834-89c5c375af28)
![Image](https://github.com/user-attachments/assets/7f6fcf5c-1f0e-4ef0-a0bc-4dfa2e0d176b)
![Image](https://github.com/user-attachments/assets/80dabc55-e4a3-4386-b79a-92a2dcefd7d0)
![Image](https://github.com/user-attachments/assets/0b651039-605d-410d-8889-9d37bfad3fc1)

VirtFusion API Integration: Connect the "Create VM" function in the admin panel to the VirtFusion REST API to automatically provision, suspend, and terminate virtual servers on your nodes.
