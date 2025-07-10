const express = require("express");
const router = express.Router();
const { db } = require("../../handlers/db");
const { isAdmin } = require("../../utils/isAdmin");

router.get("/admin/analytics", isAdmin, async (req, res) => {
  try {
    const analytics = (await db.get("analytics")) || [];

    const pageViews = analytics.reduce((acc, item) => {
      if (item?.path) {
        acc[item.path] = (acc[item.path] || 0) + 1;
      }
      return acc;
    }, {});

    const methodCounts = analytics.reduce((acc, item) => {
      if (item?.method) {
        acc[item.method] = (acc[item.method] || 0) + 1;
      }
      return acc;
    }, {});

    const timeSeriesData = analytics
      .filter((item) => item?.timestamp && item?.path)
      .map((item) => ({
        timestamp: item.timestamp,
        path: item.path,
      }));

    res.render("admin/analytics", {
      req,
      user: req.user,
      pageViews,
      methodCounts,
      timeSeriesData,
      name: "Admin Analytics",
      logo: true,
    });
  } catch (error) {
    console.error("Error in /admin/analytics:", error);
    res.status(500).render("error", { error: "Failed to load analytics data" });
  }
});

router.get("/api/analytics", isAdmin, async (req, res) => {
  try {
    // Check if user is authenticated and has admin rights
    if (!req.user || !req.user.admin) {
      return res.status(403).json({ error: "Unauthorized" });
    }

    const analytics = (await db.get("analytics")) || [];

    // Process analytics data
    const totalRequests = analytics.length;
    const uniqueVisitors = new Set(
      analytics.map((item) => item?.ip).filter(Boolean),
    ).size;
    const avgRequestsPerHour = totalRequests > 0 ? totalRequests / 24 : 0; // Avoid division by zero

    // Get page counts with safety checks
    const pageCounts = analytics.reduce((acc, item) => {
      if (item?.path) {
        acc[item.path] = (acc[item.path] || 0) + 1;
      }
      return acc;
    }, {});

    // Safely get top page
    const sortedPages = Object.entries(pageCounts).sort((a, b) => b[1] - a[1]);
    const topPage =
      sortedPages.length > 0 ? sortedPages[0][0] : "No pages visited";

    // Traffic over time (hourly)
    const trafficOverTime = Array(24).fill(0);
    analytics.forEach((item) => {
      if (item?.timestamp) {
        try {
          const hour = new Date(item.timestamp).getHours();
          if (!isNaN(hour) && hour >= 0 && hour < 24) {
            trafficOverTime[hour]++;
          }
        } catch (e) {
          console.error("Invalid timestamp:", item.timestamp);
        }
      }
    });

    // Top 5 pages
    const topPages = sortedPages.slice(0, 5);

    res.json({
      totalRequests,
      uniqueVisitors,
      avgRequestsPerHour,
      topPage,
      trafficOverTime: {
        labels: Array.from({ length: 24 }, (_, i) => `${i}:00`),
        data: trafficOverTime,
      },
      topPages: {
        labels: topPages.map(([page]) => page),
        data: topPages.map(([, count]) => count),
      },
    });
  } catch (error) {
    console.error("Error in /api/analytics:", error);
    res.status(500).json({ error: "Failed to process analytics data" });
  }
});

module.exports = router;
