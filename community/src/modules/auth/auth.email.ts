import { Resend } from "resend";

let resend: Resend | undefined;

function getResend(): Resend {
  const apiKey = process.env.RESEND_API_KEY;

  if (!apiKey) {
    throw new Error("Community email provider is not configured");
  }

  if (!resend) {
    resend = new Resend(apiKey);
  }

  return resend;
}

function getSender(): string {
  const sender = process.env.EMAIL_FROM;

  if (!sender) {
    throw new Error("Community email sender is not configured");
  }

  return sender;
}

export async function sendCommunityEmail(input: {
  to: string;
  subject: string;
  html: string;
  text: string;
}): Promise<void> {
  const client = getResend();

  const { error } = await client.emails.send({
    from: getSender(),
    to: input.to,
    subject: input.subject,
    html: input.html,
    text: input.text
  });

  if (error) {
    throw new Error("Community email delivery failed");
  }
}
