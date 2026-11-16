import type { FastifyPluginAsync } from "fastify";
import { z } from "zod";

import { getPrisma } from "../../lib/database.js";
import { requireAuth } from "../../lib/require-auth.js";
import { sendCommunityEmail } from "../auth/auth.email.js";

const feedbackSchema = z.object({
  overallRating: z.number().int().min(1).max(5),
  designRating: z.number().int().min(1).max(5).optional(),
  gamesRating: z.number().int().min(1).max(5).optional(),
  speedRating: z.number().int().min(1).max(5).optional(),
  experienceRating: z.number().int().min(1).max(5).optional(),
  recommendation: z.enum(["yes", "no", "maybe"]),
  message: z.string().trim().max(1500).optional(),
  website: z.string().max(200).optional()
}).strict();

const paginationSchema = z.object({
  page: z.coerce.number().int().min(1).default(1),
  limit: z.coerce.number().int().min(1).max(100).default(25)
});

function getAdminEmails(): string[] {
  return (process.env.FEEDBACK_ADMIN_EMAILS ?? "")
    .split(",")
    .map(email => email.trim().toLowerCase())
    .filter(Boolean);
}

async function requireFeedbackAdmin(
  request: Parameters<typeof requireAuth>[0],
  reply: Parameters<typeof requireAuth>[1]
) {
  const auth = await requireAuth(request, reply);

  if (!auth) return null;

  const allowedEmails = getAdminEmails();

  if (allowedEmails.length === 0) {
    return reply.code(403).send({
      error: "Feedback admin access is not configured"
    });
  }

  const prisma = getPrisma();

  const user = await prisma.communityUser.findUnique({
    where: { id: auth.id },
    select: { email: true }
  });

  if (!user || !allowedEmails.includes(user.email.toLowerCase())) {
    return reply.code(403).send({
      error: "Feedback admin access denied"
    });
  }

  return auth;
}

const feedbackRoutes: FastifyPluginAsync = async app => {
  // PUBLIC: Submit feedback. Login is optional.
  app.post(
    "/",
    {
      config: {
        rateLimit: {
          max: 3,
          timeWindow: 60 * 60 * 1000
        }
      }
    },
    async (request, reply) => {
      const parsed = feedbackSchema.safeParse(request.body);

      if (!parsed.success) {
        return reply.code(400).send({
          error: "Invalid feedback data"
        });
      }

      const body = parsed.data;

      // Honeypot: silently accept bot submissions without storing them.
      if (body.website?.trim()) {
        return reply.code(202).send({
          message: "Thank you for your feedback"
        });
      }

      let userId: string | null = null;

      // A supplied token must be valid. Invalid tokens are not treated
      // as anonymous submissions.
      if (request.headers.authorization !== undefined) {
        if (!request.headers.authorization.startsWith("Bearer ")) {
          return reply.code(401).send({
            error: "Invalid authorization header"
          });
        }

        const auth = await requireAuth(request, reply);

        if (!auth) return;

        userId = auth.id;
      }

      try {
        const prisma = getPrisma();

        const feedback = await prisma.feedback.create({
          data: {
            userId,
            overallRating: body.overallRating,
            designRating: body.designRating,
            gamesRating: body.gamesRating,
            speedRating: body.speedRating,
            experienceRating: body.experienceRating,
            recommendation: body.recommendation,
            message: body.message || null
          },
          select: {
            id: true,
            createdAt: true
          }
        });

        // Send a notification to the SHARX inbox after saving feedback.
        try {
          const rating = (value: number | undefined) =>
            value === undefined ? "Not provided" : `${value}/5`;

          const recommendation = {
            yes: "Yes",
            no: "No",
            maybe: "Maybe"
          }[body.recommendation];

          const message = body.message?.trim() || "No written comment";

          const escapeHtml = (value: string) =>
            value.replace(/[&<>"']/g, char => ({
              "&": "&amp;",
              "<": "&lt;",
              ">": "&gt;",
              '"': "&quot;",
              "'": "&#39;"
            })[char]!);

          await sendCommunityEmail({
            to: "hello@sharx.in",
            subject: `New SHARX feedback — ${body.overallRating}/5`,
            text: [
              "New feedback received on SHARX",
              "",
              `Overall rating: ${rating(body.overallRating)}`,
              `Design: ${rating(body.designRating)}`,
              `Games: ${rating(body.gamesRating)}`,
              `Speed: ${rating(body.speedRating)}`,
              `Experience: ${rating(body.experienceRating)}`,
              `Would recommend: ${recommendation}`,
              "",
              "Message:",
              message,
              "",
              `Feedback ID: ${feedback.id}`,
              `Submitted: ${feedback.createdAt.toISOString()}`
            ].join("\n"),
            html: `
              <div style="font-family:Arial,sans-serif;max-width:600px;margin:auto;color:#172033">
                <h2>New SHARX feedback 🎮</h2>
                <p>Someone just submitted feedback on SHARX.</p>
                <table style="border-collapse:collapse;width:100%">
                  <tr><td style="padding:8px;border-bottom:1px solid #eee">Overall</td><td style="padding:8px;border-bottom:1px solid #eee"><strong>${rating(body.overallRating)}</strong></td></tr>
                  <tr><td style="padding:8px;border-bottom:1px solid #eee">Design</td><td style="padding:8px;border-bottom:1px solid #eee">${rating(body.designRating)}</td></tr>
                  <tr><td style="padding:8px;border-bottom:1px solid #eee">Games</td><td style="padding:8px;border-bottom:1px solid #eee">${rating(body.gamesRating)}</td></tr>
                  <tr><td style="padding:8px;border-bottom:1px solid #eee">Speed</td><td style="padding:8px;border-bottom:1px solid #eee">${rating(body.speedRating)}</td></tr>
                  <tr><td style="padding:8px;border-bottom:1px solid #eee">Experience</td><td style="padding:8px;border-bottom:1px solid #eee">${rating(body.experienceRating)}</td></tr>
                  <tr><td style="padding:8px">Would recommend?</td><td style="padding:8px">${recommendation}</td></tr>
                </table>
                <h3>Message</h3>
                <p style="white-space:pre-wrap;background:#f5f5f5;padding:14px;border-radius:8px">${escapeHtml(message)}</p>
                <p style="font-size:12px;color:#777">Feedback ID: ${feedback.id}<br>Submitted: ${feedback.createdAt.toISOString()}</p>
              </div>
            `
          });
        } catch (emailError) {
          request.log.error(emailError, "Feedback saved, but notification email failed");
        }

        return reply.code(201).send({
          message: "Thank you for your feedback!",
          feedback
        });
      } catch (error) {
        request.log.error(error);

        return reply.code(500).send({
          error: "Unable to submit feedback"
        });
      }
    }
  );

  // ADMIN: Feedback statistics and paginated responses.
  app.get("/admin", async (request, reply) => {
    const admin = await requireFeedbackAdmin(request, reply);

    if (!admin || reply.sent) return;

    const pagination = paginationSchema.safeParse(request.query);

    if (!pagination.success) {
      return reply.code(400).send({
        error: "Invalid pagination parameters"
      });
    }

    const { page, limit } = pagination.data;

    try {
      const prisma = getPrisma();

      const [total, aggregate, distribution, recommendationStats, feedback] =
        await Promise.all([
          prisma.feedback.count(),

          prisma.feedback.aggregate({
            _avg: {
              overallRating: true,
              designRating: true,
              gamesRating: true,
              speedRating: true,
              experienceRating: true
            }
          }),

          prisma.feedback.groupBy({
            by: ["overallRating"],
            _count: { _all: true },
            orderBy: { overallRating: "asc" }
          }),

          prisma.feedback.groupBy({
            by: ["recommendation"],
            _count: { _all: true }
          }),

          prisma.feedback.findMany({
            orderBy: { createdAt: "desc" },
            skip: (page - 1) * limit,
            take: limit,
            select: {
              id: true,
              overallRating: true,
              designRating: true,
              gamesRating: true,
              speedRating: true,
              experienceRating: true,
              recommendation: true,
              message: true,
              createdAt: true,
              user: {
                select: {
                  id: true,
                  username: true,
                  email: true
                }
              }
            }
          })
        ]);

      return reply.send({
        stats: {
          total,
          averageRating: aggregate._avg.overallRating,
          averageCategoryRatings: {
            design: aggregate._avg.designRating,
            games: aggregate._avg.gamesRating,
            speed: aggregate._avg.speedRating,
            experience: aggregate._avg.experienceRating
          },
          ratingDistribution: [1, 2, 3, 4, 5].map(rating => ({
            rating,
            count:
              distribution.find(item => item.overallRating === rating)
                ?._count._all ?? 0
          })),
          recommendations: recommendationStats.map(item => ({
            answer: item.recommendation,
            count: item._count._all
          }))
        },
        pagination: {
          page,
          limit,
          total,
          totalPages: Math.ceil(total / limit)
        },
        feedback
      });
    } catch (error) {
      request.log.error(error);

      return reply.code(500).send({
        error: "Unable to fetch feedback dashboard"
      });
    }
  });
};

export default feedbackRoutes;
